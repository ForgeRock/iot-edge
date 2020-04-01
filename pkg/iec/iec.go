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

package iec

import (
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/go-ocf/go-coap"
	"io/ioutil"
	"log"
)

var DebugLogger = log.New(ioutil.Discard, "", 0)

// IEC represents an Identity Edge Controller
type IEC struct {
	Client *things.AMClient
	// coap server
	coapServer *coap.Server
	coapChan   chan error
	Net        string // which protocol for COAP to use, "" defaults to UDP
}

// NewIEC creates a new IEC
func NewIEC(baseURL, realm string) *IEC {
	return &IEC{
		Client: things.NewAMClient(baseURL, realm),
	}
}

// Authenticate with the AM authTree using the given payload
func (c *IEC) Authenticate(authTree string, payload message.AuthenticatePayload) (reply message.AuthenticatePayload, err error) {
	return c.Client.Authenticate(authTree, payload)
}
