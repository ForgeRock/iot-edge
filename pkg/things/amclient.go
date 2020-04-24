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
	"github.com/ForgeRock/iot-edge/internal/amurl"
	"github.com/ForgeRock/iot-edge/internal/debug"
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	acceptAPIVersion          = "Accept-API-Version"
	serverInfoEndpointVersion = "resource=1.1"
	authNEndpointVersion      = "protocol=1.0,resource=2.1"
	commandEndpointVersion    = "protocol=2.0,resource=1.0"
	contentType               = "Content-Type"
	applicationJson           = "application/json"
	applicationJose           = "application/jose"
)

// AMClient contains information for connecting directly to AM
type AMClient struct {
	http.Client
	ServerInfoURL string
	AuthURL       string
	IoTURL        string
	cookieName    string
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

// NewAMClient returns a new client for connecting directly to AM
func NewAMClient(baseURL, realm string) *AMClient {
	r := amurl.RealmFromString(realm)
	return &AMClient{
		ServerInfoURL: fmt.Sprintf("%s/json/serverinfo/*", baseURL),
		AuthURL:       fmt.Sprintf("%s/json/authenticate?realm=%s&authIndexType=service&authIndexValue=", baseURL, r.Query()),
		IoTURL:        fmt.Sprintf("%s/json/%s/iot?_action=command", baseURL, r.Path()),
	}
}

// Initialise checks that the server can be reached and prepares the client for further communication
func (c *AMClient) Initialise() error {
	info, err := c.getServerInfo()
	if err != nil {
		return err
	}
	c.cookieName = info.CookieName
	return nil
}

// Authenticate with the AM authTree using the given payload
// This is a single round trip
func (c *AMClient) Authenticate(authTree string, auth payload.Authenticate) (reply payload.Authenticate, err error) {
	requestBody, err := json.Marshal(auth)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, c.AuthURL+authTree, bytes.NewBuffer(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return reply, err
	}
	request.Header.Add(acceptAPIVersion, authNEndpointVersion)
	request.Header.Add(contentType, applicationJson)
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
	url := c.ServerInfoURL + "?_fields=cookieName"
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return info, err
	}
	request.Header.Add(acceptAPIVersion, serverInfoEndpointVersion)
	request.Header.Add(contentType, applicationJson)
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

// IoTEndpointInfo returns the information required to create a valid signed JWT for the IoT endpoint
func (c *AMClient) IoTEndpointInfo() (info payload.IoTEndpoint, err error) {
	return payload.IoTEndpoint{
		URL:     c.IoTURL,
		Version: commandEndpointVersion,
	}, nil
}

// SendCommand sends the signed JWT to the IoT Command Endpoint
func (c *AMClient) SendCommand(tokenID string, jws string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, c.IoTURL, strings.NewReader(jws))
	if err != nil {
		DebugLogger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return nil, err
	}
	request.Header.Set(acceptAPIVersion, commandEndpointVersion)
	request.Header.Set(contentType, applicationJose)
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
