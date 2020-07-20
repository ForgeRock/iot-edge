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

package session

import (
	"crypto"
	"errors"
	"github.com/ForgeRock/iot-edge/internal/client"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"github.com/ForgeRock/iot-edge/pkg/session"
	"net/url"
	"time"
)

type DefaultSession struct {
	connection client.Connection
	token      string
	nonce      int
	key        crypto.Signer
}

func (s *DefaultSession) Token() string {
	return s.token
}

func (s *DefaultSession) HasRestrictedToken() bool {
	return s.key != nil
}

func (s *DefaultSession) SigningKey() crypto.Signer {
	return s.key
}

func (s *DefaultSession) Nonce() int {
	return s.nonce
}

func (s *DefaultSession) IncrementNonce() {
	s.nonce++
}

func (s *DefaultSession) Valid() (bool, error) {
	return s.connection.ValidateSession(s.token)
}

func (s *DefaultSession) Logout() error {
	return s.connection.LogoutSession(s.token)
}

type Builder struct {
	url        *url.URL
	realm      string
	tree       string
	timeout    time.Duration
	connection client.Connection
	handlers   []callback.Handler
}

func (b *Builder) AuthenticateWith(handlers ...callback.Handler) session.Builder {
	b.handlers = handlers
	return b
}

func (b *Builder) ConnectTo(url *url.URL) session.Builder {
	b.url = url
	return b
}

func (b *Builder) WithConnection(connection client.Connection) session.Builder {
	b.connection = connection
	return b
}

func (b *Builder) InRealm(realm string) session.Builder {
	b.realm = realm
	return b
}

func (b *Builder) WithTree(tree string) session.Builder {
	b.tree = tree
	return b
}

func (b *Builder) TimeoutRequestAfter(d time.Duration) session.Builder {
	b.timeout = d
	return b
}

func (b *Builder) Create() (session.Session, error) {
	var err error
	if b.connection == nil {
		if b.url == nil {
			return nil, errors.New("url must be provided")
		}
		b.connection, err = client.NewConnection().
			ConnectTo(b.url).
			InRealm(b.realm).
			WithTree(b.tree).
			Create()
		if err != nil {
			return nil, err
		}
	}
	auth := client.AuthenticatePayload{}
	var key crypto.Signer
	for {
		if auth, err = b.connection.Authenticate(auth); err != nil {
			return nil, err
		}

		if auth.HasSessionToken() {
			return &DefaultSession{
				connection: b.connection,
				token:      auth.TokenID,
				key:        key,
			}, nil
		}
		if key, err = callback.ProcessCallbacks(b.handlers, auth.Callbacks); err != nil {
			return nil, err
		}
	}
}
