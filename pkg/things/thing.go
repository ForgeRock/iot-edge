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
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

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
)

// authenticatePayload represents the outbound and inbound data during an authentication request
type authenticatePayload struct {
	TokenID   string     `json:"tokenId,omitempty"`
	AuthID    string     `json:"authId,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
}

// commandRequestPayload represents the outbound data during a command request
type commandRequestPayload struct {
	Command string `json:"command"`
}

func (p authenticatePayload) String() string {
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
	// initialise the client
	initialise(ctx context.Context) error

	// authenticate sends an authenticate request to the ForgeRock platform
	authenticate(ctx context.Context, request authenticatePayload) (response authenticatePayload, err error)

	// sendCommand sends a command request to the ForgeRock platform
	sendCommand(ctx context.Context, tokenID string, request commandRequestPayload) (response string, err error)
}

// AMClient contains information for connecting directly to AM
// Restrictions: Signer uses ECDSA with a P-256 curve. Sign returns the signature ans1 encoded.
type AMClient struct {
	ServerInfoURL string
	AuthURL       string
	IoTURL        string
	Signer        crypto.Signer // see restrictions
	cookieName    string
}

// NewAMClient returns a new client for connecting directly to AM
// Restrictions: Signer uses ECDSA with a P-256 curve.
func NewAMClient(baseURL, realm, authTree string, signer crypto.Signer) Client {
	r := amurl.RealmFromString(realm)
	return &AMClient{
		ServerInfoURL: fmt.Sprintf("%s/json/serverinfo/*", baseURL),
		AuthURL:       fmt.Sprintf("%s/json/authenticate?realm=%s&authIndexType=service&authIndexValue=%s", baseURL, r.Query(), authTree),
		IoTURL:        fmt.Sprintf("%s/json/%s/iot?_action=command", baseURL, r.Path()),
		Signer:        signer,
	}
}

var httpClient = &http.Client{}

func (c *AMClient) initialise(ctx context.Context) (err error) {
	var info serverInfo
	if info, err = c.getServerInfo(ctx); err != nil {
		return
	}
	c.cookieName = info.CookieName
	return nil
}

func (c *AMClient) authenticate(ctx context.Context, payload authenticatePayload) (reply authenticatePayload, err error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.AuthURL, bytes.NewBuffer(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return reply, err
	}
	request.Header.Add(acceptAPIVersion, authNEndpointVersion)
	request.Header.Add(contentType, applicationJson)
	response, err := httpClient.Do(request)
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
func (c *AMClient) getServerInfo(ctx context.Context) (info serverInfo, err error) {
	url := c.ServerInfoURL + "?_fields=cookieName"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return info, err
	}
	request.Header.Add(acceptAPIVersion, serverInfoEndpointVersion)
	request.Header.Add(contentType, applicationJson)
	response, err := httpClient.Do(request)
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

func (c *AMClient) sendCommand(ctx context.Context, tokenID string, payload commandRequestPayload) (string, error) {
	requestBody, err := c.signedJWTBody(c.IoTURL, commandEndpointVersion, tokenID, payload)
	DebugLogger.Println("Signed command request body: ", requestBody)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.IoTURL, strings.NewReader(requestBody))
	if err != nil {
		DebugLogger.Println(debug.DumpRoundTrip(request, nil))
		return "", err
	}
	request.Header.Set(acceptAPIVersion, commandEndpointVersion)
	request.Header.Set(contentType, applicationJose)
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokenID})
	response, err := httpClient.Do(request)
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

func (c AMClient) signedJWTBody(url, version, tokenID string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	// Note: nonce can be 0 as long as we create a new session for each request. If we reuse the token we need
	// to increment the nonce between requests
	opts.WithHeader("nonce", 0)

	// check that the signer is supported
	alg, err := signatureAlgorithm(c.Signer)
	if err != nil {
		return "", err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(c.Signer)

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
type Thing struct {
	Client   Client
	Handlers []CallbackHandler
}

// authenticate the Thing
func (t Thing) authenticate(ctx context.Context) (tokenID string, err error) {
	payload := authenticatePayload{}
	for {
		select {
		case <-ctx.Done():
			return tokenID, errors.New("authenticate: context done")
		default:
			if payload, err = t.Client.authenticate(ctx, payload); err != nil {
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
}

// Initialise the Thing
// TODO can we make the context optional with a default so that it does not have to be passed to every SDK call
func (t Thing) Initialise(ctx context.Context) (err error) {
	if err = t.Client.initialise(ctx); err != nil {
		return nil
	}
	_, err = t.authenticate(ctx)
	return err
}

// SendCommand to AM via the iot endpoint
// TODO remove once specific commands have been added
func (t Thing) SendCommand(ctx context.Context) (string, error) {
	tokenID, err := t.authenticate(ctx)
	if err != nil {
		return "", err
	}
	return t.Client.sendCommand(ctx, tokenID, commandRequestPayload{Command: "TEST"})
}
