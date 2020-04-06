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

package mock

import (
	"crypto"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/dchest/uniuri"
)

// Client mocks a thing.Client
type Client struct {
	AuthenticateFunc func(string, message.AuthenticatePayload) (message.AuthenticatePayload, error)
}

func (m *Client) Initialise() error {
	return nil
}

func (m *Client) Authenticate(authTree string, payload message.AuthenticatePayload) (reply message.AuthenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(authTree, payload)
	}
	reply.TokenId = uniuri.New()
	return reply, nil
}

func (m *Client) SendCommand(signer crypto.Signer, tokenID string, payload message.CommandRequestPayload) (reply string, err error) {
	panic("implement me")
}
