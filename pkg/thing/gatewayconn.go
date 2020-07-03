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

package thing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"github.com/pion/dtls/v2"
	"runtime"
	"strings"
	"time"
)

// CoAP Content-Formats registry does not contain a JOSE value, using an unassigned value
const appJOSE coap.MediaType = 11650

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

// gatewayConnection contains information for connecting to the Thing Gateway via COAP
type gatewayConnection struct {
	address string
	timeout time.Duration
	key     crypto.Signer
	client  *coap.Client
	conn    *coap.ClientConn
}

// dial returns an existing connection or creates a new one
func (c *gatewayConnection) dial() (*coap.ClientConn, error) {
	if c.conn != nil {
		return c.conn, nil
	}
	var err error
	c.client.DialTimeout = c.timeout
	c.conn, err = c.client.Dial(c.address)
	return c.conn, err
}

// context returns a context to be used with CoAP requests
func (c *gatewayConnection) context() (context.Context, context.CancelFunc) {
	if c.timeout > 0 {
		return context.WithTimeout(context.Background(), c.timeout)
	}
	return context.WithCancel(context.Background())
}

func dtlsClientConfig(cert ...tls.Certificate) *dtls.Config {
	return &dtls.Config{
		Certificates:         cert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		InsecureSkipVerify:   true,
	}
}

// Initialise checks that the server can be reached and prepares the client for further communication
func (c *gatewayConnection) initialise() (err error) {
	// create certificate
	cert, err := publicKeyCertificate(c.key)
	if err != nil {
		return err
	}
	c.client = &coap.Client{
		Net:        "udp-dtls",
		DTLSConfig: dtlsClientConfig(cert),
	}

	conn, err := c.dial()
	if err != nil {
		return err
	}
	runtime.SetFinalizer(c, func(c *gatewayConnection) {
		c.conn.Close()
	})

	timeout := c.timeout
	if timeout == 0 {
		// default ping timeout to an hour
		timeout = 3600 * time.Second
	}
	err = conn.Ping(timeout)
	return err
}

// authenticate with the AM authTree using the given payload
func (c *gatewayConnection) authenticate(payload authenticatePayload) (reply authenticatePayload, err error) {
	conn, err := c.dial()
	if err != nil {
		return reply, err
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}

	msg, err := conn.NewPostRequest("/authenticate", coap.AppJSON, bytes.NewReader(requestBody))
	if err != nil {
		return reply, err
	}

	ctx, cancel := c.context()
	defer cancel()

	response, err := conn.ExchangeWithContext(ctx, msg)
	if err != nil {
		return reply, err
	} else if response.Code() != codes.Valid {
		return reply, ErrUnauthorised
	}

	if err = json.Unmarshal(response.Payload(), &reply); err != nil {
		return reply, err
	}
	return reply, nil
}

// amInfo makes a request to the Thing Gateway for AM related information
func (c *gatewayConnection) amInfo() (info amInfoSet, err error) {
	conn, err := c.dial()
	if err != nil {
		return info, err
	}

	ctx, cancel := c.context()
	defer cancel()

	response, err := conn.GetWithContext(ctx, "/aminfo")
	if err != nil {
		return info, err
	} else if response.Code() != codes.Content {
		return info, errCoAPStatusCode{response.Code(), response.Payload()}
	}

	if err = json.Unmarshal(response.Payload(), &info); err != nil {
		return info, err
	}
	return info, nil
}

// thingEndpointPayload wraps the payload destined for the Thing endpoint with the session token
type thingEndpointPayload struct {
	Token   string `json:"token"`
	Payload string `json:"payload,omitempty"`
}

// accessToken makes an access token request with the given session token and payload
// SSO token is extracted from signed JWT by Thing Gateway
func (c *gatewayConnection) accessToken(tokenID string, content contentType, payload string) (reply []byte, err error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}

	ctx, cancel := c.context()
	defer cancel()

	var coapFormat coap.MediaType
	switch content {
	case applicationJOSE:
		coapFormat = appJOSE
	case applicationJSON:
		wrappedPayload := thingEndpointPayload{
			Token:   tokenID,
			Payload: payload,
		}
		b, err := json.Marshal(wrappedPayload)
		if err != nil {
			return nil, err
		}
		payload = string(b)
		coapFormat = coap.AppJSON
	}

	response, err := conn.PostWithContext(ctx, "/accesstoken", coapFormat, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}

	if response.Code() != codes.Changed {
		return nil, errCoAPStatusCode{response.Code(), response.Payload()}
	}
	return response.Payload(), nil
}

// attributes makes a thing attributes request with the given payload
// SSO token is extracted from signed JWT by Thing Gateway
func (c *gatewayConnection) attributes(tokenID string, content contentType, payload string, names []string) (reply []byte, err error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.context()
	defer cancel()

	var coapFormat coap.MediaType
	switch content {
	case applicationJOSE:
		coapFormat = appJOSE
	case applicationJSON:
		coapFormat = coap.AppJSON
		wrappedPayload := thingEndpointPayload{
			Token:   tokenID,
			Payload: payload,
		}
		b, err := json.Marshal(wrappedPayload)
		if err != nil {
			return nil, err
		}
		payload = string(b)
	}

	request, err := conn.NewPostRequest("/attributes", coapFormat, strings.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.SetQuery(names)
	response, err := conn.ExchangeWithContext(ctx, request)
	if err != nil {
		return nil, err
	}

	if response.Code() != codes.Changed {
		return nil, errCoAPStatusCode{response.Code(), response.Payload()}
	}
	return response.Payload(), nil
}