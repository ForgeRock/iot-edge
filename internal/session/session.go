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
	"encoding/json"
	"errors"
	"github.com/ForgeRock/iot-edge/internal/client"
	"github.com/ForgeRock/iot-edge/internal/jws"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"github.com/ForgeRock/iot-edge/pkg/session"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"net/url"
	"time"
)

type DefaultSession struct {
	connection    client.Connection
	token         string
	nonce         int
	key           crypto.Signer
	popRestricted bool
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

func (s *DefaultSession) RequestBody(url, version string, payload interface{}) ([]byte, string, error) {
	if s.popRestricted {
		if s.key == nil {
			return nil, "", errors.New("request requires a signed body, but no signing key was configured")
		}
		requestBody, err := signedJWTBody(s, url, version, payload)
		if err != nil {
			return nil, "", err
		}
		return requestBody, string(client.ApplicationJOSE), nil
	} else if payload == nil {
		return []byte(""), string(client.ApplicationJSON), nil
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, "", err
		}
		return b, string(client.ApplicationJSON), nil
	}
}

// signedRequestClaims defines the claims expected in the signed JWT provided with a signed request
type signedRequestClaims struct {
	CSRF string `json:"csrf"`
}

func signedJWTBody(session *DefaultSession, url string, version string, body interface{}) ([]byte, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", session.nonce)
	// increment the nonce so that the token can be used in a subsequent request
	session.nonce++

	sig, err := jws.NewSigner(session.key, opts)
	if err != nil {
		return nil, err
	}
	builder := jwt.Signed(sig).Claims(signedRequestClaims{CSRF: session.Token()})
	if body != nil {
		builder = builder.Claims(body)
	}
	signed, err := builder.CompactSerialize()
	if err != nil {

	}
	return []byte(signed), nil
}

type Builder struct {
	url        *url.URL
	realm      string
	tree       string
	timeout    time.Duration
	connection client.Connection
	handlers   []callback.Handler
	signer     crypto.Signer
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

func (b *Builder) SignRequestsWith(signer crypto.Signer) session.Builder {
	b.signer = signer
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
	popRestricted := false
	for {
		if auth, err = b.connection.Authenticate(auth); err != nil {
			return nil, err
		}

		if auth.HasSessionToken() {
			return &DefaultSession{
				connection:    b.connection,
				token:         auth.TokenID,
				key:           b.signer,
				popRestricted: popRestricted,
			}, nil
		}
		if popRestricted, err = processCallbacks(b.handlers, auth.Callbacks); err != nil {
			return nil, err
		}
	}
}

// processCallbacks attempts to respond to the callbacks with the given callback handlers
func processCallbacks(handlers []callback.Handler, callbacks []callback.Callback) (bool, error) {
	popRestricted := false
	for _, cb := range callbacks {
		for _, h := range handlers {
			handled, err := h.Handle(cb)
			if err != nil {
				return popRestricted, err
			}
			if !handled {
				continue
			}
			popRestricted = popRestricted || isSessionPoPRestricted(h)
			break
		}
	}
	return popRestricted, nil
}

func isSessionPoPRestricted(handler callback.Handler) bool {
	if _, ok := handler.(callback.AuthenticateHandler); ok {
		return true
	}
	if _, ok := handler.(callback.RegisterHandler); ok {
		return true
	}
	return false
}
