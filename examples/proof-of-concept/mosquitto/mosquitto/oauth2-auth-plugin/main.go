/*
 * Copyright 2020 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

/*
#include <mosquitto.h>
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>
typedef const struct mosquitto const_mosquitto;
typedef const struct mosquitto_acl_msg const_mosquitto_acl_msg;
typedef const char const_char;
*/
import "C"
import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

const (
	read      access = 0x01 // read from a topic
	write     access = 0x02 // write to a topic
	subscribe access = 0x04 // subscribe to a topic

	// configuration
	optPrefix  = "oauth2_"
	optLogDest = optPrefix + "log_dest"

	// constants used by the config file to switch log destination
	destFile   = "file"
	destStdout = "stdout"
)

var (
	logger *log.Logger
	file   *os.File = nil

	readRE  = regexp.MustCompile(`mqtt.read:([\\p{L}/#+]+)`)
	writeRE = regexp.MustCompile(`mqtt.write:([\\p{L}/#+]+)`)
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

// userData contains the persistent data that is kept between plugin calls
type userData struct {
	identity thing.Thing
	// tokenCache to store access tokens between API calls. The client pointer value is used as the key.
	tokenCache map[string]string
	mutex      sync.RWMutex
}

//export mosquitto_auth_plugin_version
/*
 * Returns the value of MOSQ_AUTH_PLUGIN_VERSION defined in the mosquitto header file that the plugin was compiled
 * against.
 */
func mosquitto_auth_plugin_version() C.int {
	return C.MOSQ_AUTH_PLUGIN_VERSION
}

//export mosquitto_auth_plugin_init
/*
 * Initialises the plugin.
 */
func mosquitto_auth_plugin_init(cUserData *unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int) C.int {
	var err error
	// copy opts from the C world into Go
	optMap := extractOptions(cOpts, cOptCount)

	// initialise logger
	if logger, file, err = initialiseLogger(optMap[optLogDest]); err != nil {
		fmt.Printf("error initialising logger, %s", err)
		return C.MOSQ_ERR_AUTH
	}
	logger.Println("Init plugin")
	thing.SetDebugLogger(logger)

	// ForgeRock connection information
	// Can be passed to the plugin via Mosquitto configuration
	thingID := "572ddcde-1532-4175-861b-0622ac2f3bf3"
	store := secrets.Store{}
	signer, err := store.Signer(thingID)
	if err != nil {
		log.Fatal(err)
	}
	certificates, err := store.Certificates(thingID)
	if err != nil {
		log.Fatal(err)
	}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, _ := url.Parse(os.Getenv("AM_URL"))
	amRealm := os.Getenv("AM_REALM")
	amTree := os.Getenv("AM_TREE")

	data := userData{
		tokenCache: make(map[string]string),
	}

	for {
		data.identity, err = builder.Thing().
			AsService().
			ConnectTo(amURL).
			InRealm(amRealm).
			WithTree(amTree).
			AuthenticateThing(thingID, amRealm, keyID, signer, nil).
			RegisterThing(certificates, nil).
			Create()
		if err == nil {
			break
		}
		logger.Printf("thing create error; %v", err)
		time.Sleep(5 * time.Second)
	}
	logger.Println("created thing")

	*cUserData = unsafe.Pointer(&data)
	logger.Println("leave - plugin init successful")
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_plugin_cleanup
/*
 * Cleans up the plugin before the server shuts down.
 */
func mosquitto_auth_plugin_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, _ C.int) C.int {
	logger.Println("enter - plugin cleanup")
	// close logfile
	if file != nil {
		file.Sync()
		file.Close()
		file = nil
	}
	// set the token cache to nil so it can be garage collected
	(*userData)(cUserData).tokenCache = nil

	logger.Println("leave - plugin cleanup")
	logger = nil
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_unpwd_check
/*
 * Authenticates the client by checking the validity of the supplied OAuth 2.0 access token given as the password.
 */
func mosquitto_auth_unpwd_check(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cUsername, cPassword *C.const_char) C.int {
	logger.Println("enter - unpwd check")
	if cUserData == nil {
		logger.Println("Missing cUserData")
		return C.MOSQ_ERR_AUTH
	}
	if cClient == nil {
		logger.Println("Missing cClient")
		return C.MOSQ_ERR_AUTH
	}
	if cUsername == nil || cPassword == nil {
		return C.MOSQ_ERR_AUTH
	}

	username := goStringFromConstant(cUsername)
	token := goStringFromConstant(cPassword)
	logger.Printf("p: %s\n", token)

	data := (*userData)(cUserData)
	introspection, err := data.identity.IntrospectAccessToken(token)
	logger.Printf("Introspection %v, %v", introspection, err)
	if err != nil {
		logger.Printf("leave - unpwd check error, %s", err)
		return C.MOSQ_ERR_AUTH
	}

	active, _ := introspection.Active()
	logger.Printf("leave - unpwd check successful, user authorised? %v", active)
	if !active {
		return C.MOSQ_ERR_PLUGIN_DEFER
	}
	data.mutex.Lock()
	data.tokenCache[username] = token
	data.mutex.Unlock()

	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_acl_check
/*
 * Checks whether a client's access token authorises it to subscribe to, read from or write to a topic.
 */
func mosquitto_auth_acl_check(cUserData unsafe.Pointer, cAccess C.int, cClient *C.const_mosquitto, cMsg *C.const_mosquitto_acl_msg) C.int {
	logger.Println("enter - acl check")
	if cUserData == nil {
		logger.Println("Missing cUserData")
		return C.MOSQ_ERR_AUTH
	}
	if cClient == nil {
		logger.Println("Missing cClient")
		return C.MOSQ_ERR_AUTH
	}

	// C -> Go
	data := (*userData)(cUserData)
	username := C.GoString(C.mosquitto_client_username(cClient))
	access := access(cAccess)
	topic := C.GoString(cMsg.topic)

	// get cache data
	data.mutex.RLock()
	token, ok := data.tokenCache[username]
	data.mutex.RUnlock()
	if !ok {
		// the user will not be in the cache if it was authenticated by mosquitto or another plugin
		return C.MOSQ_ERR_PLUGIN_DEFER
	}
	introspection, err := data.identity.IntrospectAccessToken(token)
	logger.Printf("Introspection %v, %v", introspection, err)
	if err != nil {
		logger.Printf("leave - unpwd check error, %s", err)
		return C.MOSQ_ERR_AUTH
	}
	active, _ := introspection.Active()
	if !active {
		logger.Printf("leave - acl check %s token inactive", access)
		data.mutex.Lock()
		delete(data.tokenCache, username)
		data.mutex.Unlock()
		// raising an error results in the client being disconnected by mosquitto, enabling the client to obtain a new
		// token. If DEFER is returned instead, a publish\read will fail quietly.
		return C.MOSQ_ERR_AUTH
	}

	scopes, err := introspection.Scope()
	if err != nil {
		logger.Printf("leave - unpwd check error, %s", err)
		return C.MOSQ_ERR_AUTH
	}

	allow := false
	switch access {
	case subscribe, read:
		allow = matchTopic(parseFilter(readRE, scopes), topic)
	case write:
		allow = matchTopic(parseFilter(writeRE, scopes), topic)
	default:
		logger.Printf("Unexpected access request %d\n", access)
		return C.MOSQ_ERR_AUTH
	}
	if !allow {
		logger.Printf("leave - acl check %s denied", access)
		return C.MOSQ_ERR_PLUGIN_DEFER
	}
	logger.Printf("leave - acl check %s granted", access)
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_init
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_init(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_security_cleanup
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_security_cleanup(cUserData unsafe.Pointer, cOpts *C.struct_mosquitto_opt, cOptCount C.int, cReload C.bool) C.int {
	return C.MOSQ_ERR_SUCCESS
}

//export mosquitto_auth_psk_key_get
/*
 * No-op function. Included to satisfy the plugin contract to Mosquitto.
 */
func mosquitto_auth_psk_key_get(cUserData unsafe.Pointer, cClient *C.const_mosquitto, cHint, cIdentity *C.const_char, cKey *C.char, cMaxKeyLen C.int) C.int {
	return C.MOSQ_ERR_SUCCESS
}

func main() {

}

// initialiseLogger initialises the logger depending on the fields in the supplied configuration string
// Defaults to stdout if the input string is empty or unrecognised.
// Returns an error if logging to a file is requested but fails.
func initialiseLogger(s string) (l *log.Logger, f *os.File, err error) {
	settings := strings.Fields(s)
	var w = io.Discard
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

// parseFilter parses the MQTT topic filter from the scopes
// Assumes that the filter will be found in the the first capturing group of the regexp if the entire expression matches
func parseFilter(re *regexp.Regexp, scopes []string) string {
	for _, s := range scopes {
		m := re.FindStringSubmatch(s)
		if len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
