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

type iecThingBuilder struct {
	initialiser
}

func (b *iecThingBuilder) AddHandler(h Handler) Builder {
	b.handlers = append(b.handlers, h)
	return b
}

func (b *iecThingBuilder) SetTimeout(d time.Duration) Builder {
	b.client.(*IECClient).Timeout = d
	return b
}

// IECThing returns a Builder that can setup and initialise a Thing that communicates with an IEC
func IECThing(address string, key crypto.Signer) Builder {
	return &iecThingBuilder{initialiser{client: &IECClient{Address: address, Key: key}}}
}

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

// IECClient contains information for connecting to the IEC via COAP
type IECClient struct {
	Address string
	Timeout time.Duration
	Key     crypto.Signer
	client  *coap.Client
	conn    *coap.ClientConn
}

// dial returns an existing connection or creates a new one
func (c *IECClient) dial() (*coap.ClientConn, error) {
	if c.conn != nil {
		return c.conn, nil
	}
	var err error
	c.client.DialTimeout = c.Timeout
	c.conn, err = c.client.Dial(c.Address)
	return c.conn, err
}

// context returns a context to be used with CoAP requests
func (c *IECClient) context() (context.Context, context.CancelFunc) {
	if c.Timeout > 0 {
		return context.WithTimeout(context.Background(), c.Timeout)
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
func (c *IECClient) Initialise() (err error) {
	// create certificate
	cert, err := publicKeyCertificate(c.Key)
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
	runtime.SetFinalizer(c, func(c *IECClient) {
		c.conn.Close()
	})

	timeout := c.Timeout
	if timeout == 0 {
		// default ping timeout to an hour
		timeout = 3600 * time.Second
	}
	err = conn.Ping(timeout)
	return err
}

// Authenticate with the AM authTree using the given payload
func (c *IECClient) Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
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

// AMInfo makes a request to the IEC for AM related information
func (c *IECClient) AMInfo() (info AMInfoSet, err error) {
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

// AccessToken makes an access token request with the given session token and payload
// SSO token is extracted from signed JWT by IEC
func (c *IECClient) AccessToken(_ string, jws string) (reply []byte, err error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}

	ctx, cancel := c.context()
	defer cancel()

	response, err := conn.PostWithContext(ctx, "/accesstoken", coap.AppJSON, strings.NewReader(jws))
	if err != nil {
		return nil, err
	}

	if response.Code() != codes.Changed {
		return nil, errCoAPStatusCode{response.Code(), response.Payload()}
	}
	return response.Payload(), nil
}

// Attributes makes a thing attributes request with the given payload
// SSO token is extracted from signed JWT by IEC
func (c *IECClient) Attributes(_ string, jws string, names []string) (reply []byte, err error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	ctx, cancel := c.context()
	defer cancel()

	request, err := conn.NewPostRequest("/attributes", coap.AppJSON, strings.NewReader(jws))
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
