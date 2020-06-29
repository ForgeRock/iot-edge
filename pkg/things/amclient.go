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

package things

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/debug"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	acceptAPIVersion          = "Accept-API-Version"
	serverInfoEndpointVersion = "resource=1.1"
	authNEndpointVersion      = "protocol=1.0,resource=2.1"
	thingsEndpointVersion     = "protocol=2.0,resource=1.0"
	httpContentType           = "Content-Type"
	// Query keys
	fieldQueryKey         = "_fields"
	realmQueryKey         = "realm"
	authIndexTypeQueryKey = "authIndexType"
	authTreeQueryKey      = "authIndexValue"
)

// AMClient contains information for connecting directly to AM
type AMClient struct {
	http.Client
	BaseURL string
	// Realm that the client communicates with, must be the fully-qualified name including the parent path e.g.
	// root realm; "/"
	// a sub-realm of root called "alfheim"; "/alfheim"
	// a sub-realm of alfheim called "svartalfheim"; "/alfheim/svartalfheim"
	Realm      string
	AuthTree   string
	cookieName string
}

// amError is used to unmarshal an AM error response
type amError struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func parseAMError(response []byte, status int) error {
	var amError amError
	if err := json.Unmarshal(response, &amError); err != nil {
		return fmt.Errorf("request failed with status code %d", status)
	}
	return fmt.Errorf("%s: %s", amError.Reason, amError.Message)
}

// initialise checks that the server can be reached and prepares the client for further communication
func (c *AMClient) initialise() error {
	info, err := c.getServerInfo()
	if err != nil {
		return err
	}
	c.cookieName = info.CookieName
	return nil
}

// authenticate with the AM authTree using the given payload
// This is a single round trip
func (c *AMClient) authenticate(payload authenticatePayload) (reply authenticatePayload, err error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, c.BaseURL+"/json/authenticate", bytes.NewBuffer(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return reply, err
	}

	// add realm and auth tree to query
	q := request.URL.Query()
	q.Set(realmQueryKey, c.Realm)
	q.Set(authIndexTypeQueryKey, "service")
	q.Set(authTreeQueryKey, c.AuthTree)
	request.URL.RawQuery = q.Encode()

	request.Header.Add(acceptAPIVersion, authNEndpointVersion)
	request.Header.Add(httpContentType, string(applicationJSON))
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, ErrUnauthorised
	}
	if err = json.Unmarshal(responseBody, &reply); err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	return reply, err
}

// serverInfo contains information gathered from a server information request to AM
type serverInfo struct {
	CookieName string `json:"cookieName"`
}

// getServerInfo makes a server information request to AM
func (c *AMClient) getServerInfo() (info serverInfo, err error) {
	request, err := http.NewRequest(http.MethodGet, c.BaseURL+"/json/serverinfo/*", nil)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return info, err
	}

	q := request.URL.Query()
	q.Set(fieldQueryKey, "cookieName")
	request.URL.RawQuery = q.Encode()

	request.Header.Add(acceptAPIVersion, serverInfoEndpointVersion)
	request.Header.Add(httpContentType, string(applicationJSON))
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, fmt.Errorf("server info request failed")
	}
	if err = json.Unmarshal(responseBody, &info); err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	return info, err
}

func (c *AMClient) accessTokenURL() string {
	return c.BaseURL + "/json/things/*?_action=get_access_token&realm=" + c.Realm
}

func (c *AMClient) attributesURL() string {
	return c.BaseURL + "/json/things/*?realm=" + c.Realm
}

func fieldsQuery(fields []string) string {
	if len(fields) > 0 {
		return "&_fields=" + strings.Join(fields, ",")
	}
	return ""
}

// amInfo returns AM related information to the client
func (c *AMClient) amInfo() (info amInfoSet, err error) {
	return amInfoSet{
		Realm:          c.Realm,
		AccessTokenURL: c.accessTokenURL(),
		AttributesURL:  c.attributesURL(),
		ThingsVersion:  thingsEndpointVersion,
	}, nil
}

// accessToken makes an access token request with the given session token and payload
func (c *AMClient) accessToken(tokenID string, content contentType, payload string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, c.accessTokenURL(), strings.NewReader(payload))
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return nil, err
	}
	return c.makeCommandRequest(tokenID, content, request)
}

// attributes makes a thing attributes request with the given session token and payload
func (c *AMClient) attributes(tokenID string, content contentType, payload string, names []string) (reply []byte, err error) {
	request, err := http.NewRequest(http.MethodGet, c.attributesURL()+fieldsQuery(names), strings.NewReader(payload))
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return nil, err
	}
	return c.makeCommandRequest(tokenID, content, request)
}

func (c *AMClient) makeCommandRequest(tokenID string, content contentType, request *http.Request) (reply []byte, err error) {
	request.Header.Set(acceptAPIVersion, thingsEndpointVersion)
	request.Header.Set(httpContentType, string(content))
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokenID})
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, response))
		return responseBody, parseAMError(responseBody, response.StatusCode)
	}
	return responseBody, err
}
