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
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/debug"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"time"
)

// COAPClient contains information for connecting to the IEC via COAP
type COAPClient struct {
	coap.Client
	Address string
	Timeout time.Duration
}

// NewCOAPClient returns a new client for connecting to the IEC
func NewCOAPClient(address string) *COAPClient {
	return &COAPClient{
		Address: address,
	}
}

// Initialise checks that the server can be reached and prepares the client for further communication
func (c COAPClient) Initialise() (Client, error) {
	conn, err := c.Dial(c.Address)
	if err != nil {
		return c, err
	}
	defer conn.Close()
	timeout := c.Timeout
	if timeout == 0 {
		// default ping timeout to an hour
		timeout = 3600 * time.Second
	}
	err = conn.Ping(timeout)
	return c, err
}

// Authenticate with the AM authTree using the given payload
func (c COAPClient) Authenticate(authTree string, payload message.AuthenticatePayload) (reply message.AuthenticatePayload, err error) {
	conn, err := c.Dial(c.Address)
	if err != nil {
		return reply, err
	}
	defer conn.Close()

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}

	message, err := conn.NewPostRequest("/authenticate", coap.AppJSON, bytes.NewReader(requestBody))
	if err != nil {
		return reply, err
	}
	message.SetQueryString(authTree)

	ctx := context.Background()
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.Timeout)
		defer cancel()
	}

	response, err := conn.ExchangeWithContext(ctx, message)
	if err != nil {
		DebugLogger.Println(debug.DumpCOAPRoundTrip(conn, message, response))
		return reply, err
	}
	if response.Code() != codes.Valid {
		DebugLogger.Println(debug.DumpCOAPRoundTrip(conn, message, response))
		return reply, errAuthRequest
	}
	if err = json.Unmarshal(response.Payload(), &reply); err != nil {
		DebugLogger.Println(debug.DumpCOAPRoundTrip(conn, message, response))
		return reply, err
	}
	return reply, nil
}

func (c COAPClient) sendCommand(signer crypto.Signer, tokenID string, payload message.CommandRequestPayload) (reply string, err error) {
	return reply, fmt.Errorf("not implemented")
}
