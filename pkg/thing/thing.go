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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/jws"
	"github.com/ForgeRock/iot-edge/pkg/callback"
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

// Thing represents an AM Thing identity
type Thing struct {
	connection connection
	handlers   []callback.Handler
	session    *Session
}

// Session holds session data
type Session struct {
	token string
	nonce int
	key   crypto.Signer
}

// Token returns the session token
func (s *Session) Token() string {
	return s.token
}

// HasRestrictedToken returns true if the session has a restricted token
func (s *Session) HasRestrictedToken() bool {
	return s.key != nil
}

// SigningKey returns the signing key associated with a restricted SSO token
func (s *Session) SigningKey() crypto.Signer {
	return s.key
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
	var key crypto.Signer
	for {
		if auth, err = t.connection.authenticate(auth); err != nil {
			return session, err
		}

		if auth.HasSessionToken() {
			return &Session{token: auth.TokenId, key: key}, nil
		}
		if key, err = processCallbacks(t.handlers, auth.Callbacks); err != nil {
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

// signedRequestClaims defines the claims expected in the signed JWT provided with a signed request
type signedRequestClaims struct {
	CSRF string `json:"csrf"`
}

func signedJWTBody(session *Session, url string, version string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", session.nonce)
	// increment the nonce so that the token can be used in a subsequent request
	session.IncrementNonce()

	sig, err := jws.NewSigner(session.key, opts)
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
	// WithTree sets the tree that the thing authenticates with
	WithTree(tree string) Builder
	// AsService registers the thing as a service. By default, a thing is registered as a device
	AsService() Builder
	// AuthenticateThing with the ForgeRock Authenticate Thing tree node
	AuthenticateThing(thingID string, keyID string, key crypto.Signer, claims func() interface{}) Builder
	// RegisterThing with the ForgeRock Register Thing tree node
	RegisterThing(certificates []*x509.Certificate, claims func() interface{}) Builder
	// HandleCallbacksWith the supplied handlers
	HandleCallbacksWith(handlers ...callback.Handler) Builder
	// TimeoutRequestAfter sets the timeout on the communications between the Thing and AM\Thing Gateway
	TimeoutRequestAfter(time.Duration) Builder
	// Create a Thing instance and authenticates\registers it with AM
	Create() (*Thing, error)
}

type authHandlerBuilder struct {
	thingID string
	keyID   string
	key     crypto.Signer
	claims  func() interface{}
}

type regHandlerBuilder struct {
	certificates []*x509.Certificate
	claims       func() interface{}
}

type baseBuilder struct {
	u           *url.URL
	realm       string
	tree        string
	thingType   callback.ThingType
	timeout     time.Duration
	handlers    []callback.Handler
	authHandler *authHandlerBuilder
	regHandler  *regHandlerBuilder
}

func (b *baseBuilder) AsService() Builder {
	b.thingType = callback.TypeService
	return b
}

func (b *baseBuilder) AuthenticateThing(thingID string, keyID string, key crypto.Signer, claims func() interface{}) Builder {
	b.authHandler = &authHandlerBuilder{
		thingID: thingID,
		keyID:   keyID,
		key:     key,
		claims:  claims,
	}
	return b
}

func (b *baseBuilder) RegisterThing(certificates []*x509.Certificate, claims func() interface{}) Builder {
	b.regHandler = &regHandlerBuilder{
		certificates: certificates,
		claims:       claims,
	}
	return b
}

func (b *baseBuilder) ConnectTo(u *url.URL) Builder {
	b.u = u
	return b
}

func (b *baseBuilder) HandleCallbacksWith(handlers ...callback.Handler) Builder {
	b.handlers = handlers
	return b
}

func (b *baseBuilder) InRealm(realm string) Builder {
	b.realm = realm
	return b
}

func (b *baseBuilder) WithTree(tree string) Builder {
	b.tree = tree
	return b
}

func (b *baseBuilder) TimeoutRequestAfter(d time.Duration) Builder {
	b.timeout = d
	return b
}

// createKID creates a key ID for a signer
func createKID(key crypto.Signer) (string, error) {
	thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(thumbprint), nil
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
	if b.authHandler != nil {
		// check we have a signer
		if b.authHandler.key == nil {
			return nil, fmt.Errorf("no key to authenticate thing with")
		}
		info, err := client.amInfo()
		if err != nil {
			return nil, err
		}
		auth := callback.AuthenticateHandler{
			Realm:   info.Realm,
			ThingID: b.authHandler.thingID,
			KeyID:   b.authHandler.keyID,
			Key:     b.authHandler.key,
			Claims:  b.authHandler.claims,
		}
		if b.regHandler != nil {
			if auth.KeyID == "" {
				auth.KeyID, err = createKID(auth.Key)
				if err != nil {
					return nil, err
				}
			}
			b.handlers = append(b.handlers, callback.RegisterHandler{
				Realm:        info.Realm,
				ThingID:      auth.ThingID,
				ThingType:    b.thingType,
				KeyID:        auth.KeyID,
				Key:          auth.Key,
				Certificates: b.regHandler.certificates,
				Claims:       b.regHandler.claims,
			})
		}
		b.handlers = append(b.handlers, auth)

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
	return &baseBuilder{
		thingType: callback.TypeDevice,
	}
}

// processCallbacks attempts to respond to the callbacks with the given callback handlers
func processCallbacks(handlers []callback.Handler, callbacks []callback.Callback) (key crypto.Signer, err error) {
	for _, cb := range callbacks {
	handlerLoop:
		for _, h := range handlers {
			switch err = h.Handle(cb); err {
			case callback.ErrNotHandled:
				continue
			case nil:
				if r, ok := h.(callback.ProofOfPossessionHandler); ok {
					key = r.SigningKey()
				}
				break handlerLoop
			default:
				DebugLogger.Println(err)
				continue
			}
		}
		if err != nil {
			return key, err
		}
	}
	return key, nil
}
