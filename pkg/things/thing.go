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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"net/url"
	"time"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

var (
	ErrBuilderNoConnection      = errors.New("builder has no defined connection")
	ErrBuilderUnsupportedScheme = errors.New("builder connecting with unsupported scheme")
	ErrUnauthorised             = errors.New("unauthorised")
)

type contentType string

const (
	applicationJSON contentType = "application/json"
	applicationJOSE contentType = "application/jose"
)

// connection to the ForgeRock platform
type connection interface {
	// initialise the client. Must be called before the Client is used by a Thing
	initialise() error

	// authenticate sends an authenticate request to the ForgeRock platform
	authenticate(payload authenticatePayload) (reply authenticatePayload, err error)

	// amInfo returns the information required to construct valid signed JWTs
	amInfo() (info amInfoSet, err error)

	// accessToken makes an access token request with the given session token and payload
	accessToken(tokenID string, content contentType, payload string) (reply []byte, err error)

	// attributes makes a thing attributes request with the given session token and payload
	attributes(tokenID string, content contentType, payload string, names []string) (reply []byte, err error)
}

// ThingType describes the Thing type
type ThingType string

const (
	TypeDevice  ThingType = "device"
	TypeService ThingType = "service"
	TypeGateway ThingType = "gateway"
)

// Thing represents an AM Thing identity
type Thing struct {
	connection connection
	handlers   []Handler
	session    *Session
}

// Session holds session data
type Session struct {
	token           string
	nonce           int
	confirmationKey crypto.Signer
}

// Token returns the session token
func (s *Session) Token() string {
	return s.token
}

// HasRestrictedToken returns true if the session has a restricted token
func (s *Session) HasRestrictedToken() bool {
	return s.confirmationKey != nil
}

// ConfirmationKey returns the signing key associated with a restricted SSO token
func (s *Session) ConfirmationKey() crypto.Signer {
	return s.confirmationKey
}

// Nonce returns the session nonce
func (s *Session) Nonce() int {
	return s.nonce
}

// IncrementNonce increments the session nonce
func (s *Session) IncrementNonce() {
	s.nonce++
}

// authenticate the Thing
func (t *Thing) authenticate() (session *Session, err error) {
	auth := authenticatePayload{}
	metadata := AuthMetadata{}
	for {
		if auth, err = t.connection.authenticate(auth); err != nil {
			return session, err
		}

		if auth.HasSessionToken() {
			return &Session{token: auth.TokenId, confirmationKey: metadata.ConfirmationKey}, nil
		}
		if err = processCallbacks(t, t.handlers, auth.Callbacks, &metadata); err != nil {
			return session, err
		}
	}
}

// Session returns a session for the Thing
func (t *Thing) Session() (session *Session, err error) {
	if t.session == nil {
		session, err = t.authenticate()
		if err != nil {
			return session, err
		}
		t.session = session
	}
	return t.session, nil
}

func signedJWTBody(session *Session, url string, version string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", session.nonce)
	// increment the nonce so that the token can be used in a subsequent request
	session.IncrementNonce()

	sig, err := newJOSESigner(session.confirmationKey, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).Claims(signedRequestClaims{CSRF: session.token})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

// RequestAccessToken requests an OAuth 2.0 access token for a thing. The provided scopes will be included in the token
// if they are configured in the thing's associated OAuth 2.0 Client in AM. If no scopes are provided then the token
// will include the default scopes configured in the OAuth 2.0 Client.
func (t *Thing) RequestAccessToken(scopes ...string) (response AccessTokenResponse, err error) {
	session, err := t.Session()
	if err != nil {
		return
	}

	payload := getAccessTokenPayload{Scope: scopes}
	var requestBody string
	var content contentType
	if session.HasRestrictedToken() {
		info, err := t.connection.amInfo()
		if err != nil {
			return response, err
		}
		requestBody, err = signedJWTBody(session, info.AccessTokenURL, info.ThingsVersion, payload)
		if err != nil {
			return response, err
		}
		content = applicationJOSE
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			return response, err
		}
		requestBody = string(b)
		content = applicationJSON
	}
	reply, err := t.connection.accessToken(session.token, content, requestBody)
	if reply != nil {
		DebugLogger.Println("RequestAccessToken response: ", string(reply))
	}
	if err != nil {
		return
	}
	err = json.Unmarshal(reply, &response.Content)
	DebugLogger.Println("RequestAccessToken request completed successfully")
	return
}

// RequestAttributes requests the attributes with the specified names associated with the thing's identity.
// If no names are specified then all the allowed attributes will be returned.
func (t *Thing) RequestAttributes(names ...string) (response AttributesResponse, err error) {
	session, err := t.Session()
	if err != nil {
		return
	}

	var requestBody string
	var content contentType
	if session.HasRestrictedToken() {
		info, err := t.connection.amInfo()
		if err != nil {
			return response, err
		}
		requestBody, err = signedJWTBody(session, info.AttributesURL+fieldsQuery(names), info.ThingsVersion, nil)
		if err != nil {
			return response, err
		}
		content = applicationJOSE
	} else {
		content = applicationJSON
	}
	reply, err := t.connection.attributes(session.token, content, requestBody, names)
	if reply != nil {
		DebugLogger.Println("RequestAttributes response: ", string(reply))
	}
	if err != nil {
		return
	}
	err = json.Unmarshal(reply, &response.Content)
	DebugLogger.Println("RequestAttributes request completed successfully")
	return
}

// Realm returns the Thing's AM realm
func (t *Thing) Realm() string {
	info, err := t.connection.amInfo()
	if err != nil {
		DebugLogger.Println(err)
	}
	return info.Realm
}

// Builder interface provides methods to setup and initialise a Thing
type Builder interface {
	// ConnectTo to the server at the given URL
	ConnectTo(url *url.URL) Builder
	// InRealm sets which realm the thing belongs to
	// Note that the realm must be the fully-qualified name including the parent path e.g.
	// root realm; "/"
	// a sub-realm of root called "alfheim"; "/alfheim"
	// a sub-realm of alfheim called "svartalfheim"; "/alfheim/svartalfheim"
	InRealm(realm string) Builder
	// AuthenticateWith the named authentication tree
	AuthenticateWith(tree string) Builder
	// HandleCallbacksWith the supplied handlers
	HandleCallbacksWith(handlers ...Handler) Builder
	// TimeoutRequestAfter sets the timeout on the communications between the Thing and AM\Thing Gateway
	TimeoutRequestAfter(time.Duration) Builder
	// Create a Thing instance and authenticates\registers it with AM
	Create() (*Thing, error)
}

type baseBuilder struct {
	u        *url.URL
	realm    string
	tree     string
	timeout  time.Duration
	handlers []Handler
}

func (b *baseBuilder) ConnectTo(u *url.URL) Builder {
	b.u = u
	return b
}

func (b *baseBuilder) HandleCallbacksWith(handlers ...Handler) Builder {
	b.handlers = handlers
	return b
}

func (b *baseBuilder) InRealm(realm string) Builder {
	b.realm = realm
	return b
}

func (b *baseBuilder) AuthenticateWith(tree string) Builder {
	b.tree = tree
	return b
}

func (b *baseBuilder) TimeoutRequestAfter(d time.Duration) Builder {
	b.timeout = d
	return b
}

func (b *baseBuilder) Create() (*Thing, error) {
	if b.u == nil {
		return nil, ErrBuilderNoConnection
	}
	var client connection
	switch b.u.Scheme {
	case "http", "https":
		client = &amConnection{baseURL: b.u.String(), realm: b.realm, authTree: b.tree}
	case "coap", "coaps":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		client = &gatewayConnection{address: b.u.Host, key: key}
	default:
		return nil, ErrBuilderUnsupportedScheme
	}
	err := client.initialise()
	if err != nil {
		return nil, err
	}
	thing := &Thing{
		connection: client,
		handlers:   b.handlers,
	}
	_, err = thing.authenticate()
	if err != nil {
		return thing, err
	}
	return thing, err
}

// New returns a new Thing builder
func New() Builder {
	return &baseBuilder{}
}
