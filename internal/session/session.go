/*
 * Copyright 2020-2022 ForgeRock AS
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
	"reflect"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/session"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type DefaultSession struct {
	connection client.Connection
	token      string
}

func (s *DefaultSession) Token() string {
	return s.token
}

func (s *DefaultSession) Valid() (bool, error) {
	return s.connection.ValidateSession(s.token, client.ApplicationJSON, "")
}

func (s *DefaultSession) Logout() error {
	return s.connection.LogoutSession(s.token, client.ApplicationJSON, "")
}

// PoPSession is produced when the thing was authenticated using a signed JWT.
type PoPSession struct {
	DefaultSession
	nonce int
	key   crypto.Signer
}

// SignRequestBody will sign the request in order to satisfy the Proof of Possession restriction added to AM sessions.
func (s *PoPSession) SignRequestBody(url, version string, body interface{}) (signedJWT string, err error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", s.nonce)
	// increment the nonce so that the token can be used in a subsequent request
	s.nonce++
	sig, err := jws.NewSigner(s.key, opts)
	if err != nil {
		return
	}
	builder := jwt.Signed(sig).Claims(struct {
		CSRF string `json:"csrf"`
	}{
		CSRF: s.Token(),
	})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

func (s *PoPSession) Valid() (bool, error) {
	info, err := s.connection.AMInfo()
	if err != nil {
		return false, err
	}
	requestBody, err := s.SignRequestBody(info.SessionValidateURL, info.SessionsVersion, nil)
	if err != nil {
		return false, err
	}
	return s.connection.ValidateSession(s.token, client.ApplicationJOSE, requestBody)
}

func (s *PoPSession) Logout() error {
	info, err := s.connection.AMInfo()
	if err != nil {
		return err
	}
	requestBody, err := s.SignRequestBody(info.SessionLogoutURL, info.SessionsVersion, nil)
	if err != nil {
		return err
	}
	return s.connection.LogoutSession(s.token, client.ApplicationJOSE, requestBody)
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
	if !reflect.ValueOf(b.connection).IsValid() {
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
	if handler, ok := handler.(callback.JWTPoPHandler); ok {
		return handler.AuthenticateHandler.Key
	}
	return nil
}
