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
	"encoding/json"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/debug"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"strings"
	"time"
)

type errCoAPStatusCode struct {
	code    codes.Code
	payload []byte
}

func (e errCoAPStatusCode) Error() string {
	msg := fmt.Sprintf("code: %v", e.code)
	if e.payload != nil {
		msg += fmt.Sprintf(", payload: %s", string(e.payload))
	}
	return msg
}

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
func (c COAPClient) Initialise() error {
	conn, err := c.Dial(c.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	timeout := c.Timeout
	if timeout == 0 {
		// default ping timeout to an hour
		timeout = 3600 * time.Second
	}
	err = conn.Ping(timeout)
	return err
}

type requestFunc func(conn *coap.ClientConn) (coap.Message, error)
type responseFunc func(coap.Message) ([]byte, error)

// exchange performs a synchronous query
func (c *COAPClient) exchange(msgFunc requestFunc, postFunc responseFunc) ([]byte, error) {
	conn, err := c.Dial(c.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	message, err := msgFunc(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), c.Timeout)
		defer cancel()
	}

	response, err := conn.ExchangeWithContext(ctx, message)
	if err != nil {
		DebugLogger.Println(debug.DumpCOAPRoundTrip(conn, message, response))
		return nil, err
	}
	return postFunc(response)
}

// Authenticate with the AM authTree using the given payload
func (c COAPClient) Authenticate(authTree string, payload message.AuthenticatePayload) (reply message.AuthenticatePayload, err error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}

	responseBody, err := c.exchange(func(conn *coap.ClientConn) (c coap.Message, err error) {
		c, err = conn.NewPostRequest("/authenticate", coap.AppJSON, bytes.NewReader(requestBody))
		if err != nil {
			return
		}
		c.SetQueryString(authTree)
		return
	}, func(c coap.Message) (i []byte, err error) {
		if c.Code() != codes.Valid {
			return nil, ErrUnauthorised
		}
		return c.Payload(), nil
	})
	if err != nil {
		return reply, err
	}

	if err = json.Unmarshal(responseBody, &reply); err != nil {
		return reply, err
	}
	return reply, nil
}

// IoTEndpointInfo returns the information required to create a valid signed JWT for the IoT endpoint
func (c COAPClient) IoTEndpointInfo() (info message.IoTEndpoint, err error) {
	responseBody, err := c.exchange(func(conn *coap.ClientConn) (c coap.Message, err error) {
		c, err = conn.NewGetRequest("/iotendpointinfo")
		if err != nil {
			return
		}
		return
	}, func(c coap.Message) (i []byte, err error) {
		if c.Code() != codes.Content {
			return nil, errCoAPStatusCode{c.Code(), c.Payload()}
		}
		return c.Payload(), nil
	})
	if err != nil {
		return info, err
	}

	if err = json.Unmarshal(responseBody, &info); err != nil {
		return info, err
	}
	return info, nil
}

// SendCommand sends the signed JWT to the IoT Command Endpoint
func (c COAPClient) SendCommand(tokenID string, jws string) (reply []byte, err error) {
	return c.exchange(func(conn *coap.ClientConn) (c coap.Message, err error) {
		c, err = conn.NewPostRequest("/sendcommand", coap.AppJSON, strings.NewReader(jws))
		if err != nil {
			return
		}
		return
	}, func(c coap.Message) (i []byte, err error) {
		if c.Code() != codes.Changed {
			return nil, errCoAPStatusCode{c.Code(), c.Payload()}
		}
		return c.Payload(), nil
	})
}
