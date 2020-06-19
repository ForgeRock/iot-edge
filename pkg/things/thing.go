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
	"encoding/json"
	"errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
	"time"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

var (
	ErrUnauthorised = errors.New("unauthorised")
)

// Client is an interface that describes the connection to the ForgeRock platform
type Client interface {
	// Initialise the client. Must be called before the Client is used by a Thing
	Initialise() error

	// Authenticate sends an Authenticate request to the ForgeRock platform
	Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error)

	// AMInfo returns the information required to construct valid signed JWTs
	AMInfo() (info AMInfoSet, err error)

	// AccessToken makes an access token request with the given session token and payload
	AccessToken(tokenID string, jws string) (reply []byte, err error)
}

// ThingType describes the Thing type
type ThingType string

const (
	TypeDevice ThingType = "device"
	TypeIEC    ThingType = "iec"
)

// Thing represents an AM Thing identity
type Thing struct {
	Client   Client
	handlers []Handler
	session  *Session
}

// NewThing creates a new Thing
func NewThing(client Client, handlers []Handler) *Thing {
	return &Thing{
		Client:   client,
		handlers: handlers,
	}
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
	auth := AuthenticatePayload{}
	metadata := AuthMetadata{}
	for {
		if auth, err = t.Client.Authenticate(auth); err != nil {
			return session, err
		}

		if auth.HasSessionToken() {
			return &Session{token: auth.TokenId, confirmationKey: metadata.ConfirmationKey}, nil
		}
		if err = ProcessCallbacks(t, t.handlers, auth.Callbacks, &metadata); err != nil {
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

	// check that the signer is supported
	alg, err := signingJWAFromKey(session.confirmationKey)
	if err != nil {
		return "", err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(session.confirmationKey)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
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
	info, err := t.Client.AMInfo()
	if err != nil {
		return
	}
	requestBody, err := signedJWTBody(session, info.AccessTokenURL, info.ThingsVersion, NewGetAccessToken(scopes))
	if err != nil {
		return
	}
	reply, err := t.Client.AccessToken(session.token, requestBody)
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

// Realm returns the Thing's AM realm
func (t *Thing) Realm() string {
	info, err := t.Client.AMInfo()
	if err != nil {
		DebugLogger.Println(err)
	}
	return info.Realm
}

// Builder interface provides methods to setup and initialise a Thing
type Builder interface {
	// AddHandler adds a callback handler
	AddHandler(Handler) Builder
	// SetTimeout sets the timeout on the communications between the Thing and AM\IEC
	SetTimeout(time.Duration) Builder
	// Initialise a Thing instance and authenticates\registers it with AM
	Initialise() (*Thing, error)
}

type initialiser struct {
	client   Client
	handlers []Handler
}

func (b *initialiser) Initialise() (*Thing, error) {
	err := b.client.Initialise()
	if err != nil {
		return nil, err
	}
	thing := &Thing{
		Client:   b.client,
		handlers: b.handlers,
	}
	_, err = thing.authenticate()
	if err != nil {
		return thing, err
	}
	return thing, err
}
