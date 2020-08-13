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
	"net/url"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/session"
)

type DefaultSession struct {
	connection client.Connection
	token      string
}

func (s *DefaultSession) Token() string {
	return s.token
}

func (s *DefaultSession) Valid() (bool, error) {
	return s.connection.ValidateSession(s.token)
}

func (s *DefaultSession) Logout() error {
	return s.connection.LogoutSession(s.token)
}

type PoPSession struct {
	DefaultSession
	nonce int
	key   crypto.Signer
}

func (s *PoPSession) SigningKey() crypto.Signer {
	return s.key
}

func (s *PoPSession) Nonce() int {
	return s.nonce
}

func (s *PoPSession) IncrementNonce() {
	s.nonce++
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
	var signer crypto.Signer
	for {
		if auth, err = b.connection.Authenticate(auth); err != nil {
			return nil, err
		}

		if auth.HasSessionToken() {
			defaultSession := DefaultSession{
				connection: b.connection,
				token:      auth.TokenID,
			}
			if signer != nil {
				return &PoPSession{
					DefaultSession: defaultSession,
					key:            signer,
				}, nil
			}
			return &defaultSession, nil
		}
		if signer, err = processCallbacks(b.handlers, auth.Callbacks); err != nil {
			return nil, err
		}
	}
}

// processCallbacks attempts to respond to the callbacks with the given callback handlers
func processCallbacks(handlers []callback.Handler, callbacks []callback.Callback) (signer crypto.Signer, err error) {
	for _, cb := range callbacks {
		for _, h := range handlers {
			handled, err := h.Handle(cb)
			if err != nil {
				return nil, err
			}
			if !handled {
				continue
			}
			if signer == nil {
				signer = handlerSigningKey(h)
			}
			break
		}
	}
	return signer, nil
}

func handlerSigningKey(handler callback.Handler) crypto.Signer {
	if handler, ok := handler.(callback.AuthenticateHandler); ok {
		return handler.Key
	}
	if handler, ok := handler.(callback.RegisterHandler); ok {
		return handler.Key
	}
	return nil
}
