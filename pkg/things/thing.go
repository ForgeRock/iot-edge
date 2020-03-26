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
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/internal/amurl"
	"github.com/ForgeRock/iot-edge/internal/debug"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

const (
	acceptAPIVersion          = "Accept-API-Version"
	serverInfoEndpointVersion = "resource=1.1"
	authNEndpointVersion      = "protocol=1.0,resource=2.1"
	commandEndpointVersion    = "protocol=2.0,resource=1.0"
	contentType               = "Content-Type"
	applicationJson           = "application/json"
	applicationJose           = "application/jose"

	defaultTimeout = 5 * time.Second
)

// AuthenticatePayload represents the outbound and inbound data during an authentication request
type AuthenticatePayload struct {
	TokenID   string     `json:"tokenId,omitempty"`
	AuthID    string     `json:"authId,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
}

// commandRequestPayload represents the outbound data during a command request
type commandRequestPayload struct {
	Command string `json:"command"`
}

func (p AuthenticatePayload) String() string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "\t")
	if err != nil {
		return ""
	}
	return out.String()
}

// Client is an interface that describes the connection to the ForgeRock platform
type Client interface {
	// Initialise the client. Must be called before the Client is used by a Thing
	Initialise() (Client, error)

	// Authenticate sends an Authenticate request to the ForgeRock platform
	Authenticate(authTree string, payload AuthenticatePayload) (reply AuthenticatePayload, err error)

	// sendCommand sends a command request to the ForgeRock platform
	sendCommand(signer crypto.Signer, tokenID string, payload commandRequestPayload) (reply string, err error)
}

// AMClient contains information for connecting directly to AM
type AMClient struct {
	http.Client
	ServerInfoURL string
	AuthURL       string
	IoTURL        string
	cookieName    string
}

// NewAMClient returns a new client for connecting directly to AM
func NewAMClient(baseURL, realm string) *AMClient {
	r := amurl.RealmFromString(realm)
	return &AMClient{
		Client:        http.Client{Timeout: defaultTimeout},
		ServerInfoURL: fmt.Sprintf("%s/json/serverinfo/*", baseURL),
		AuthURL:       fmt.Sprintf("%s/json/authenticate?realm=%s&authIndexType=service&authIndexValue=", baseURL, r.Query()),
		IoTURL:        fmt.Sprintf("%s/json/%s/iot?_action=command", baseURL, r.Path()),
	}
}

// Initialise the AM client
func (c *AMClient) Initialise() (Client, error) {
	info, err := c.getServerInfo()
	if err != nil {
		return c, err
	}
	c.cookieName = info.CookieName
	return c, nil
}

// Authenticate with the AM authTree using the given payload
// This is a single round trip
func (c *AMClient) Authenticate(authTree string, payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, c.AuthURL+authTree, bytes.NewBuffer(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return reply, err
	}
	request.Header.Add(acceptAPIVersion, authNEndpointVersion)
	request.Header.Add(contentType, applicationJson)
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return reply, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return reply, err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return reply, fmt.Errorf("authentication request failed")
	}
	if err = json.Unmarshal(responseBody, &reply); err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
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
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return info, err
	}
	request.Header.Add(acceptAPIVersion, serverInfoEndpointVersion)
	request.Header.Add(contentType, applicationJson)
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return info, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return info, err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return info, fmt.Errorf("server info request failed")
	}
	if err = json.Unmarshal(responseBody, &info); err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return info, err
	}
	return info, err
}

func (c *AMClient) sendCommand(signer crypto.Signer, tokenID string, payload commandRequestPayload) (string, error) {
	requestBody, err := signedJWTBody(signer, c.IoTURL, commandEndpointVersion, tokenID, payload)
	DebugLogger.Println("Signed command request body: ", requestBody)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequest(http.MethodPost, c.IoTURL, strings.NewReader(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return "", err
	}
	request.Header.Set(acceptAPIVersion, commandEndpointVersion)
	request.Header.Set(contentType, applicationJose)
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokenID})
	response, err := c.Do(request)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return "", err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return "", err
	}
	if response.StatusCode != http.StatusOK {
		DebugLogger.Println(debug.DumpRoundTrip(request, response))
		return "", fmt.Errorf("request for command %s failed", payload.Command)
	}
	return string(responseBody), err
}

func signedJWTBody(signer crypto.Signer, url, version, tokenID string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	// Note: nonce can be 0 as long as we create a new session for each request. If we reuse the token we need
	// to increment the nonce between requests
	opts.WithHeader("nonce", 0)

	// check that the signer is supported
	alg, err := signatureAlgorithm(signer)
	if err != nil {
		return "", err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(signer)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).Claims(struct {
		Csrf string `json:"csrf"`
	}{Csrf: tokenID})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

// Thing represents an AM Thing identity
// Restrictions: Signer uses ECDSA with a P-256 curve. Sign returns the signature ans1 encoded.
type Thing struct {
	Signer   crypto.Signer // see restrictions
	AuthTree string
	Handlers []CallbackHandler
}

// authenticate the Thing
func (t Thing) authenticate(client Client) (tokenID string, err error) {
	payload := AuthenticatePayload{}
	for {
		if payload, err = client.Authenticate(t.AuthTree, payload); err != nil {
			return tokenID, err
		}

		if payload.TokenID != "" {
			return payload.TokenID, nil
		}
		if err = processCallbacks(payload.Callbacks, t.Handlers); err != nil {
			return tokenID, err
		}
	}
}

// Initialise the Thing
func (t Thing) Initialise(client Client) (err error) {
	_, err = t.authenticate(client)
	return err
}

// SendCommand to AM via the iot endpoint
// TODO remove once specific commands have been added
func (t Thing) SendCommand(client Client) (string, error) {
	tokenID, err := t.authenticate(client)
	if err != nil {
		return "", err
	}
	return client.sendCommand(t.Signer, tokenID, commandRequestPayload{Command: "TEST"})
}
