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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/tokencache"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/go-ocf/go-coap"
	"io/ioutil"
	"log"
	"time"
)

var DebugLogger = log.New(ioutil.Discard, "", 0)

func init() {
	things.DebugLogger = DebugLogger
}

// IEC represents an Identity Edge Controller
type IEC struct {
	Client    things.Client
	authCache *tokencache.Cache
	// coap server
	coapServer *coap.Server
	coapChan   chan error
	Net        string // which protocol for COAP to use, "" defaults to UDP
}

// NewIEC creates a new IEC
func NewIEC(baseURL, realm string) *IEC {
	return &IEC{
		Client:    things.NewAMClient(baseURL, realm),
		authCache: tokencache.New(5*time.Minute, 10*time.Minute),
	}
}

// Initialise the IEC
func (c *IEC) Initialise() error {
	return c.Client.Initialise()
}

// Authenticate with the AM authTree using the given payload
func (c *IEC) Authenticate(authTree string, payload message.AuthenticatePayload) (reply message.AuthenticatePayload, err error) {
	if payload.AuthIDKey != "" {
		payload.AuthId, _ = c.authCache.Get(payload.AuthIDKey)
	}
	payload.AuthIDKey = ""

	reply, err = c.Client.Authenticate(authTree, payload)
	if err != nil {
		return
	}

	// if reply has a token, authentication has successfully completed
	if reply.HasSessionToken() {
		return reply, nil
	}

	if reply.AuthId == "" {
		return reply, fmt.Errorf("no Auth Id in reply")
	}

	// Auth ID as it is usually too big for a single UDP message.
	// Instead, create a shorter key and cache the Auth Id, returning the key to the caller.
	// Use the hash value of the id as its key
	d := sha256.Sum256([]byte(reply.AuthId))
	reply.AuthIDKey = base64.StdEncoding.EncodeToString(d[:])
	c.authCache.Add(reply.AuthIDKey, reply.AuthId)
	reply.AuthId = ""

	return
}
