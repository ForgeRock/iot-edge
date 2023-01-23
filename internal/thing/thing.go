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

package thing

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	isession "github.com/ForgeRock/iot-edge/v7/internal/session"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/session"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

const (
	// Device authorization grant constants: https://tools.ietf.org/html/rfc8628#section-3.5
	authorizationPending = "authorization_pending"
	slowDown             = "slow_down"
	intervalDefault      = time.Second * 5 // https://tools.ietf.org/html/rfc8628#section-3.2
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
		if err == nil || !client.CodeUnauthorized.IsWrappedIn(err) {
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

func (t *DefaultThing) RequestAccessToken(scopes ...string) (response thing.AccessTokenResponse, err error) {
	payload := client.GetAccessTokenPayload{Scope: scopes}
	return t.accessToken(payload)
}

func (t *DefaultThing) RefreshAccessToken(refreshToken string, scopes ...string) (response thing.AccessTokenResponse,
	err error) {
	payload := client.GetAccessTokenPayload{Scope: scopes, RefreshToken: refreshToken}
	return t.accessToken(payload)
}

func (t *DefaultThing) accessToken(payload client.GetAccessTokenPayload) (response thing.AccessTokenResponse, err error) {
	var requestBody string
	var content client.ContentType

	err = t.makeAuthorisedRequest(func(session session.Session) error {
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			requestBody, err = popSession.SignRequestBody(info.AccessTokenURL, info.ThingsVersion, payload)
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
	var requestBody string
	var content client.ContentType
	payload := client.IntrospectPayload{Token: token}

	err = t.makeAuthorisedRequest(func(session session.Session) error {
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			requestBody, err = popSession.SignRequestBody(info.IntrospectURL, info.ThingsVersion, payload)
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
		reply, err := t.connection.IntrospectAccessToken(session.Token(), content, requestBody)
		if reply != nil {
			debug.Logger.Println("IntrospectAccessToken response: ", string(reply))
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(reply, &introspection.Content)
	})
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
			requestBody, err = popSession.SignRequestBody(urlString, info.ThingsVersion, nil)
			if err != nil {
				return err
			}
			content = client.ApplicationJOSE
		} else {
			content = client.ApplicationJSON
		}
		reply, err := t.connection.Attributes(session.Token(), content, requestBody, names)
		if reply != nil {
			debug.Logger.Println("RequestAttributes response: ", string(reply))
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(reply, &response.Content)
	})
	return response, err
}

func (t *DefaultThing) RequestUserCode(scopes ...string) (response thing.DeviceAuthorizationResponse, err error) {
	payload := struct {
		Scope []string `json:"scope,omitempty"`
	}{Scope: scopes}
	var requestBody string
	var content client.ContentType

	err = t.makeAuthorisedRequest(func(session session.Session) error {
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			requestBody, err = popSession.SignRequestBody(info.UserCodeURL, info.ThingsVersion, payload)
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
		reply, err := t.connection.UserCode(session.Token(), content, requestBody)
		if reply != nil {
			debug.Logger.Println("RequestUserCode response: ", string(reply))
		}
		if err != nil {
			return err
		}
		return json.Unmarshal(reply, &response)
	})
	return response, err
}

func (t *DefaultThing) RequestUserToken(authorizationResponse thing.DeviceAuthorizationResponse) (
	tokenResponse thing.AccessTokenResponse, err error) {

	payload := struct {
		DeviceCode string `json:"device_code,omitempty"`
	}{
		DeviceCode: authorizationResponse.DeviceCode,
	}
	interval := intervalDefault
	if authorizationResponse.Interval > 0 {
		interval = time.Second * time.Duration(authorizationResponse.Interval)
	}
	var responseBytes []byte
	authorisedRequest := func(session session.Session) error {
		var content client.ContentType
		var requestBody string
		if popSession, ok := session.(*isession.PoPSession); ok {
			info, err := t.connection.AMInfo()
			if err != nil {
				return err
			}
			requestBody, err = popSession.SignRequestBody(info.UserTokenURL, info.ThingsVersion, payload)
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
		responseBytes, err = t.connection.UserToken(session.Token(), content, requestBody)
		if responseBytes != nil {
			debug.Logger.Println("RequestUserToken response: ", string(responseBytes))
		}
		return err
	}
	for {
		err = t.makeAuthorisedRequest(authorisedRequest)
		// an error occurred, but we have no response to process
		if err != nil && responseBytes == nil {
			return
		}
		// no error, so we can assume the token was issued
		if err == nil {
			err = json.Unmarshal(responseBytes, &tokenResponse.Content)
			return
		}
		// process the response message, the OAuth2 error is wrapped inside the "detail" section
		var errorResponse struct {
			Detail struct {
				Error string `json:"error"`
			} `json:"detail"`
		}
		err = json.Unmarshal(responseBytes, &errorResponse)
		if err != nil {
			debug.Logger.Println("Unrecognized error response: ", string(responseBytes))
			return
		}
		switch errorResponse.Detail.Error {
		case authorizationPending:
			// Nothing to do, just wait the interval and request the tokens again
		case slowDown:
			// Increase poling time by 5 seconds, see https://tools.ietf.org/html/rfc8628#section-3.5
			interval += intervalDefault
		default:
			debug.Logger.Println("Error response: ", string(responseBytes))
			return tokenResponse, errors.New(errorResponse.Detail.Error)
		}
		time.Sleep(interval)
	}
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
	if !reflect.ValueOf(b.connection).IsValid() {
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
