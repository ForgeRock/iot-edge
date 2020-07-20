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

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
)

type ContentType string

const (
	ApplicationJSON ContentType = "application/json"
	ApplicationJOSE ContentType = "application/jose"
)

var ErrUnauthorised = errors.New("unauthorised")

// connection to the ForgeRock platform
type Connection interface {
	// initialise the client. Must be called before the Client is used by a Thing
	Initialise() error

	// authenticate sends an authenticate request to the ForgeRock platform
	Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error)

	// amInfo returns the information required to construct valid signed JWTs
	AMInfo() (info AMInfoResponse, err error)

	// validateSession sends a validate session request
	ValidateSession(tokenID string) (ok bool, err error)

	// logoutSession makes a request to logout the session
	LogoutSession(tokenID string) (err error)

	// accessToken makes an access token request with the given session token and payload
	AccessToken(tokenID string, content ContentType, payload string) (reply []byte, err error)

	// attributes makes a thing attributes request with the given session token and payload
	Attributes(tokenID string, content ContentType, payload string, names []string) (reply []byte, err error)
}

type ConnectionBuilder struct {
	url   *url.URL
	realm string
	tree  string
	key   crypto.Signer
}

func NewConnection() *ConnectionBuilder {
	return &ConnectionBuilder{}
}

func (b *ConnectionBuilder) ConnectTo(url *url.URL) *ConnectionBuilder {
	b.url = url
	return b
}

func (b *ConnectionBuilder) InRealm(realm string) *ConnectionBuilder {
	b.realm = realm
	return b
}

func (b *ConnectionBuilder) WithTree(tree string) *ConnectionBuilder {
	b.tree = tree
	return b
}

func (b *ConnectionBuilder) WithKey(key crypto.Signer) *ConnectionBuilder {
	b.key = key
	return b
}

func (b *ConnectionBuilder) Create() (Connection, error) {
	var connection Connection
	switch b.url.Scheme {
	case "http", "https":
		connection = &amConnection{baseURL: b.url.String(), realm: b.realm, authTree: b.tree}
	case "coap", "coaps":
		var err error
		if b.key == nil {
			b.key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			return nil, err
		}
		connection = &gatewayConnection{address: b.url.Host, key: b.key}
	default:
		return nil, fmt.Errorf("unsupported scheme `%s`, must be one of http(s) or coap(s)", b.url.Scheme)
	}
	err := connection.Initialise()
	return connection, err
}
