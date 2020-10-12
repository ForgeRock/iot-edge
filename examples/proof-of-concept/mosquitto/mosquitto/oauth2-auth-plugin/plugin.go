package main

import (
	"encoding/json"
	"fmt"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"
	"unsafe"
)

var (
	readRE  = regexp.MustCompile(`mqtt:read:([\\p{L}/#\+]+)`)
	writeRE = regexp.MustCompile(`mqtt:write:([\\p{L}/#\+]+)`)
)

// access describes the type of access to a topic that the client is requesting
type access int

func (a access) String() string {
	switch a {
	case read:
		return "read"
	case write:
		return "write"
	case subscribe:
		return "subscribe"
	default:
		return "unknown"
	}
}

const (
	read      access = 0x01 // read from a topic
	write     access = 0x02 // write to a topic
	subscribe access = 0x04 // subscribe to a topic
)

// clientAuthorisation contains the authorisation granted to the client
type clientAuthorisation struct {
	write      string
	read       string
	expiration time.Time
}

// userData contains the persistent data that is kept between plugin calls
type userData struct {
	endpoint     string
	clientID     string
	clientSecret string
	t            thing.Thing
	// clientCache to store client data between API calls. The client pointer value is used as the key.
	clientCache map[unsafe.Pointer]clientAuthorisation
}

// Introspect creates a request to introspect the given OAuth2 token
func (u userData) Introspect(token string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodPost,
		u.endpoint,
		strings.NewReader(fmt.Sprintf("token=%s", token)))

	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(u.clientID, u.clientSecret)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

const (
	optPrefix = "openam_"

	optEndpoint     = optPrefix + "endpoint"
	optClientID     = optPrefix + "client_id"
	optClientSecret = optPrefix + "client_secret"
	// optional
	optLogDest = optPrefix + "log_dest"
)

var requiredOpts = [...]string{
	optEndpoint,
	optClientID,
	optClientSecret,
}

// initialiseUserData initialises the data shared between plugin calls
func initialiseUserData(opts map[string]string) (userData, error) {
	var data userData
	// check all the required options have been supplied
	for _, o := range requiredOpts {
		if _, ok := opts[o]; !ok {
			return data, fmt.Errorf("missing field %s", o)
		}
	}

	// copy over user data values
	data.endpoint = opts[optEndpoint]
	data.clientID = opts[optClientID]
	data.clientSecret = opts[optClientSecret]

	// make client cache
	data.clientCache = make(map[unsafe.Pointer]clientAuthorisation)
	return data, nil
}

const (
	// constants used by the config file to switch log destination
	destNone   = "none"
	destFile   = "file"
	destStdout = "stdout"
)

// initialiseLogger initialises the logger depending on the fields in the supplied configuration string
// Defaults to stdout if the input string is empty or unrecognised.
// Returns an error if logging to a file is requested but fails.
func initialiseLogger(s string) (l *log.Logger, f *os.File, err error) {
	settings := strings.Fields(s)
	var w = ioutil.Discard
	if len(settings) > 0 {
		switch settings[0] {
		case destFile:
			if len(settings) < 2 {
				return l, f, fmt.Errorf("file path missing")
			}
			var err error
			f, err = os.OpenFile(settings[1], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return l, f, err
			}
			w = f
		case destStdout:
			w = os.Stdout
		default:
			fmt.Printf("WARNING: unknown debug setting, %s", settings)
		}
	}
	return log.New(w, "AUTH_PLUGIN: ", log.LstdFlags|log.Lmsgprefix), f, nil
}

// clearUserData clears the userData struct so that memory can be garbage collected
func clearUserData(user *userData) {
	user.clientCache = nil
}

// doer is an interface that represents a http client
type doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpResponseError indicates that an unexpected response has been returned by the server
type httpResponseError struct {
	response *http.Response
}

func (e httpResponseError) Error() string {
	statusCode := e.response.StatusCode
	if b, err := httputil.DumpResponse(e.response, true); err == nil {
		return string(b)
	}
	return fmt.Sprintf("received status code %d", statusCode)
}

const (
	retryLimit = 4
)

// withBackOff retries the do function with back off until the max retry limit has been reached
func withBackOff(maxRetry int, do func() (bool, *http.Response, error)) (response *http.Response, err error) {
	const backOff = 100 * time.Millisecond
	retry := true
	for i, b := 0, time.Duration(0); retry && i < maxRetry; i, b = i+1, b+backOff {
		time.Sleep(b) // a zero duration will return immediately
		retry, response, err = do()
	}
	return
}

// checkResponseStatusCode checks the status code of the response and decides whether a retry is required
func checkResponseStatusCode(response *http.Response) (bool, error) {
	switch response.StatusCode {
	case http.StatusOK:
		return false, nil
	case http.StatusInternalServerError, http.StatusServiceUnavailable:
		return true, httpResponseError{response}
	default:
		return false, httpResponseError{response}
	}
}

// Checks whether a client is authorised to write or read to a topic.
func authorise(httpDo doer, user *userData, access access, client unsafe.Pointer, topic string) (bool, error) {
	// get cache data
	authData, ok := user.clientCache[client]
	if !ok {
		// the user will not be in the cache if it was authenticated by mosquitto or another plugin
		return false, nil
	}

	// check whether the token has expired
	logger.Println(authData)
	if time.Now().After(authData.expiration) {
		logger.Println("Token has expired")
		return false, nil
	}

	allow := false
	switch access {
	case subscribe, read:
		allow = matchTopic(authData.read, topic)
	case write:
		allow = matchTopic(authData.write, topic)
	default:
		return false, fmt.Errorf("Unexpected access request %d\n", access)
	}
	return allow, nil
}

// parseFilter parses the MQTT topic filter from the scopes
// Assumes that the filter will be found in the the first capturing group of the regexp if the entire expression matches
func parseFilter(re *regexp.Regexp, scope string) string {
	m := re.FindStringSubmatch(scope)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

/*
 * authenticate the client by checking the supplied username and password.
 * an OAuth2 Access Token is passed in as the password.
 */
func authenticate(httpDo doer, user *userData, client unsafe.Pointer, username, password string) (bool, error) {
	response, err := withBackOff(retryLimit, func() (retry bool, response *http.Response, err error) {
		request, err := user.Introspect(password)
		if err != nil {
			err = fmt.Errorf("failed to create a OAuth2 ID Token verification request, %s", err)
			return false, nil, err
		}
		response, err = httpDo.Do(request)
		if err != nil {
			return true, response, err
		}
		retry, err = checkResponseStatusCode(response)
		return retry, response, err
	})
	if err != nil {
		return false, fmt.Errorf("OAuth2 ID Token verification failed, %s", err)
	}

	defer response.Body.Close()
	introspectionBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var introspection struct {
		Active bool   `json:"active"`
		Scope  string `json:"scope"`
		Exp    int64  `json:"exp"`
	}
	if err := json.Unmarshal(introspectionBytes, &introspection); err != nil {
		return false, err
	}

	if !introspection.Active {
		logger.Println("Introspection indicates that the token is inactive")
		return false, nil
	}

	write := parseFilter(writeRE, introspection.Scope)
	read := parseFilter(readRE, introspection.Scope)
	if write == "" && read == "" {
		logger.Println("Not authorised to write or read")
		return false, nil
	}

	// add client authorisation data to cache
	user.clientCache[client] = clientAuthorisation{
		write:      write,
		read:       read,
		expiration: time.Unix(introspection.Exp, 0),
	}

	return true, nil
}
