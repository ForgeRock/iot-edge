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
	"crypto"
	"encoding/json"
	"errors"
	"github.com/ForgeRock/iot-edge/pkg/things/callback"
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

var (
	ErrUnauthorised = errors.New("unauthorised")
)

// Client is an interface that describes the connection to the ForgeRock platform
type Client interface {
	// Initialise the client. Must be called before the Client is used by a Thing
	Initialise() error

	// Authenticate sends an Authenticate request to the ForgeRock platform
	Authenticate(authTree string, payload payload.Authenticate) (reply payload.Authenticate, err error)

	// IoTEndpointInfo returns the information required to create a valid signed JWT for the IoT endpoint
	IoTEndpointInfo() (info payload.IoTEndpoint, err error)

	// SendCommand sends the signed JWT to the IoT Command Endpoint
	SendCommand(tokenID string, jws string) (reply []byte, err error)
}

// Thing represents an AM Thing identity
// Restrictions: Signer uses ECDSA with a P-256 curve. Sign returns the signature ans1 encoded.
type Thing struct {
	Signer   crypto.Signer // see restrictions
	AuthTree string
	Handlers []callback.Handler
}

// authenticate the Thing
func (t Thing) authenticate(client Client) (tokenID string, err error) {
	payload := payload.Authenticate{}
	for {
		if payload, err = client.Authenticate(t.AuthTree, payload); err != nil {
			return tokenID, err
		}

		if payload.HasSessionToken() {
			return payload.TokenId, nil
		}
		if err = callback.ProcessCallbacks(payload.Callbacks, t.Handlers); err != nil {
			return tokenID, err
		}
	}
}

// Initialise the Thing
func (t Thing) Initialise(client Client) (err error) {
	_, err = t.authenticate(client)
	return err
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
	builder := jwt.Signed(sig).Claims(sendCommandClaims{CSRF: tokenID})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

// RequestAccessToken requests an OAuth 2.0 access token for a thing. The provided scopes will be included in the token
// if they are configured in the thing's associated OAuth 2.0 Client in AM. If no scopes are provided then the token
// will include the default scopes configured in the OAuth 2.0 Client.
func (t Thing) RequestAccessToken(client Client, scopes ...string) (response payload.AccessTokenResponse, err error) {
	tokenID, err := t.authenticate(client)
	if err != nil {
		return
	}
	iotInfo, err := client.IoTEndpointInfo()
	if err != nil {
		return
	}
	requestBody, err := signedJWTBody(t.Signer, iotInfo.URL, iotInfo.Version, tokenID, payload.NewGetAccessTokenV1(scopes))
	if err != nil {
		return
	}
	reply, err := client.SendCommand(tokenID, requestBody)
	if reply != nil {
		DebugLogger.Println("RequestAccessToken response: ", string(reply))
	}
	if err != nil {
		return
	}
	err = json.Unmarshal(reply, &response.Content)
	DebugLogger.Println("RequestAccessToken request completed successfully")
	return
}
