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
	"errors"
	"io/ioutil"
	"log"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

var (
	errAuthRequest = errors.New("authentication request failed")
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
