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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	isession "github.com/ForgeRock/iot-edge/v7/internal/session"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/session"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type DefaultThing struct {
	connection client.Connection
	handlers   []callback.Handler
	session    session.Session
}

func (t *DefaultThing) Logout() error {
	return t.session.Logout()
}

// makeAuthorisedRequest makes a request that requires a session token
// if the session has expired, the session is renewed and the request is repeated
func (t *DefaultThing) makeAuthorisedRequest(f func(session session.Session) error) (err error) {
	for i := 0; i < 2; i++ {
		err = f(t.session)
		if err == nil || !errors.Is(err, client.ErrUnauthorised) {
			return err
		}
		valid, validateErr := t.session.Valid()
		if validateErr != nil || valid {
			return err
		}
		builder := &isession.Builder{}
		t.session, err = builder.
			WithConnection(t.connection).
			AuthenticateWith(t.handlers...).
			Create()
		if err != nil {
			return err
		}
	}
	return err
}

// signedRequestClaims defines the claims expected in the signed JWT provided with a signed request
type signedRequestClaims struct {
	CSRF string `json:"csrf"`
}

func signedJWTBody(session *isession.PoPSession, url string, version string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", session.Nonce())
	// increment the nonce so that the token can be used in a subsequent request
	session.IncrementNonce()

	sig, err := jws.NewSigner(session.SigningKey(), opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).Claims(signedRequestClaims{CSRF: session.Token()})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

func (t *DefaultThing) RequestAccessToken(scopes ...string) (response thing.AccessTokenResponse, err error) {
	payload := client.GetAccessTokenPayload{Scope: scopes}
	var requestBody string
	var content client.ContentType

	err = t.makeAuthorisedRequest(func(session session.Session) error {
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			requestBody, err = signedJWTBody(popSession, info.AccessTokenURL, info.ThingsVersion, payload)
			if err != nil {
				return err
			}
			content = client.ApplicationJOSE
		} else {
			b, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			requestBody = string(b)
			content = client.ApplicationJSON
		}
		reply, err := t.connection.AccessToken(session.Token(), content, requestBody)
		if reply != nil {
			debug.Logger.Println("RequestAccessToken response: ", string(reply))
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(reply, &response.Content)
	})
	return response, err
}

func (t *DefaultThing) IntrospectAccessToken(token string) (introspection thing.IntrospectionResponse, err error) {
	b, err := t.connection.IntrospectAccessToken(token)
	if err != nil {
		debug.Logger.Println("Introspection error", err)
		return introspection, err
	}
	err = json.Unmarshal(b, &introspection.Content)
	return introspection, err
}

func (t *DefaultThing) RequestAttributes(names ...string) (response thing.AttributesResponse, err error) {
	err = t.makeAuthorisedRequest(func(session session.Session) error {
		var requestBody string
		var content client.ContentType
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			urlString := info.AttributesURL
			if len(names) > 0 {
				// Add the names as a '_field' query to the url but the url may have queries already
				// The url.Values Encode method would have been ideal but the encoding of '/' breaks the audience check
				// in AM
				u, err := url.ParseRequestURI(urlString)
				if err != nil {
					return err
				}
				prefix := "?"
				if len(u.Query()) > 0 {
					prefix = "&"
				}
				urlString += prefix + "_fields=" + strings.Join(names, ",")
			}
			requestBody, err = signedJWTBody(popSession, urlString, info.ThingsVersion, nil)
			if err != nil {
				return err
			}
			content = client.ApplicationJOSE
		} else {
			content = client.ApplicationJSON
		}
		reply, err := t.connection.Attributes(session.Token(), content, requestBody, names)
		if err != nil {
			debug.Logger.Println("RequestAttributes response: ", string(reply))
			return err
		}
		return json.Unmarshal(reply, &response.Content)
	})
	return response, err
}

type authHandlerBuilder struct {
	thingID  string
	audience string
	keyID    string
	key      crypto.Signer
	claims   func() interface{}
}

type regHandlerBuilder struct {
	certificates []*x509.Certificate
	claims       func() interface{}
}

type BaseBuilder struct {
	u           *url.URL
	realm       string
	tree        string
	thingType   callback.ThingType
	timeout     time.Duration
	handlers    []callback.Handler
	authHandler *authHandlerBuilder
	regHandler  *regHandlerBuilder
	connection  client.Connection
}

func (b *BaseBuilder) AsService() thing.Builder {
	b.thingType = callback.TypeService
	return b
}

func (b *BaseBuilder) AuthenticateThing(thingID string, audience string, keyID string, key crypto.Signer, claims func() interface{}) thing.Builder {
	b.authHandler = &authHandlerBuilder{
		thingID:  thingID,
		audience: audience,
		keyID:    keyID,
		key:      key,
		claims:   claims,
	}
	return b
}

func (b *BaseBuilder) RegisterThing(certificates []*x509.Certificate, claims func() interface{}) thing.Builder {
	b.regHandler = &regHandlerBuilder{
		certificates: certificates,
		claims:       claims,
	}
	return b
}

func (b *BaseBuilder) ConnectTo(u *url.URL) thing.Builder {
	b.u = u
	return b
}

func (b *BaseBuilder) HandleCallbacksWith(handlers ...callback.Handler) thing.Builder {
	b.handlers = handlers
	return b
}

func (b *BaseBuilder) InRealm(realm string) thing.Builder {
	b.realm = realm
	return b
}

func (b *BaseBuilder) WithTree(tree string) thing.Builder {
	b.tree = tree
	return b
}

func (b *BaseBuilder) TimeoutRequestAfter(d time.Duration) thing.Builder {
	b.timeout = d
	return b
}

func (b *BaseBuilder) WithConnection(connection client.Connection) thing.Builder {
	b.connection = connection
	return b
}

func (b *BaseBuilder) Create() (thing.Thing, error) {
	if b.connection == nil {
		if b.u == nil {
			return nil, errors.New("URL must be provided via ConnectTo")
		}
		var err error
		b.connection, err = client.NewConnection().
			ConnectTo(b.u).
			InRealm(b.realm).
			WithTree(b.tree).
			TimeoutRequestAfter(b.timeout).
			Create()
		if err != nil {
			return nil, err
		}
	}
	if b.authHandler != nil {
		// check we have a signer and key ID
		if b.authHandler.key == nil {
			return nil, fmt.Errorf("authenticate thing requires Key")
		}
		if b.authHandler.keyID == "" {
			return nil, fmt.Errorf("authenticate thing requires Key ID")
		}
		b.handlers = append(b.handlers, callback.AuthenticateHandler{
			Audience: b.authHandler.audience,
			ThingID:  b.authHandler.thingID,
			KeyID:    b.authHandler.keyID,
			Key:      b.authHandler.key,
			Claims:   b.authHandler.claims,
		})
		if b.regHandler != nil {
			if b.thingType == "" {
				b.thingType = callback.TypeDevice
			}
			b.handlers = append(b.handlers, callback.RegisterHandler{
				Audience:     b.authHandler.audience,
				ThingID:      b.authHandler.thingID,
				ThingType:    b.thingType,
				KeyID:        b.authHandler.keyID,
				Key:          b.authHandler.key,
				Certificates: b.regHandler.certificates,
				Claims:       b.regHandler.claims,
			})
		}
	}
	builder := &isession.Builder{}
	thingSession, err := builder.
		WithConnection(b.connection).
		AuthenticateWith(b.handlers...).
		Create()
	if err != nil {
		return nil, err
	}
	return &DefaultThing{
		connection: b.connection,
		handlers:   b.handlers,
		session:    thingSession,
	}, nil
}
