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
	"encoding/base64"
	"log"
	"net/url"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"gopkg.in/square/go-jose.v2"
)

// DebugLogger is the destination of all SDK debug information. The logger is muted by default. Redirect the debug
// output by assigning your own logger to this variable or setting the output writer, for example:
//
//    thing.DebugLogger().SetOutput(os.Stdout)
func DebugLogger() *log.Logger {
	return debug.Logger
}

// SetDebugLogger will replace the default debug logger.
func SetDebugLogger(logger *log.Logger) {
	if logger != nil {
		debug.Logger = logger
	}
}

// Thing represents a device or a service with a digital identity in the ForgeRock Identity Platform.
type Thing interface {

	// RequestAccessToken requests an OAuth 2.0 access token for a thing. The provided scopes will be included in the token
	// if they are configured in the thing's associated OAuth 2.0 Client in AM. If no scopes are provided then the token
	// will include the default scopes configured in the OAuth 2.0 Client.
	RequestAccessToken(scopes ...string) (response AccessTokenResponse, err error)

	// IntrospectAccessToken introspects an OAuth 2.0 access token for a thing as defined by rfc7662.
	// Supports only client-based OAuth 2.0 tokens signed with an asymmetric key.
	IntrospectAccessToken(token string) (introspection IntrospectionResponse, err error)

	// RequestAttributes requests the attributes with the specified names associated with the thing's identity.
	// If no names are specified then all the allowed attributes will be returned.
	RequestAttributes(names ...string) (response AttributesResponse, err error)

	// Logout will invalidate the thing's session with AM. It is good practice to log out if the thing will not make
	// new requests for a prolonged period. Once logged out the thing will automatically create a new session when a
	// new request is made.
	Logout() error
}

// Builder interface provides methods to setup and initialise a Thing.
type Builder interface {

	// ConnectTo the server at the given URL.
	// Supports http(s) for connecting to AM and coap(s) for connecting to the Thing Gateway.
	// When connecting to AM, the URL should be either the top level realm in AM or the DNS alias of a sub realm.
	ConnectTo(url *url.URL) Builder

	// InRealm specifies the path to the AM realm in which the thing should authenticate and operate in.
	// This can be a realm alias or the fully qualified realm path, for example:
	//  - root realm: "/"
	//  - a sub-realm of root called "alfheim": "/alfheim"
	//  - a sub-realm of alfheim called "svartalfheim": "/alfheim/svartalfheim"
	//
	// The realm should not be set if a DNS alias is being used to connect to AM.
	// The realm is not required if the thing is connecting to the Thing Gateway. If provided it will be ignored.
	InRealm(realm string) Builder

	// WithTree sets the name of the AM authentication tree that will be used to register and authenticate the thing.
	// The tree is not required if the thing is connecting to the Thing Gateway. If provided it will be ignored.
	WithTree(tree string) Builder

	// AsService registers the thing as a service. By default, a thing is registered as a device.
	AsService() Builder

	// AuthenticateThing with the ForgeRock Authenticate Thing tree node. This node uses JWT PoP and requires a JWT
	// signed with the key that was registered for the thing. The JWT must contain the key ID provided for the
	// registered key. In addition, the JWT may include custom claims about the thing. The claims will be available for
	// processing by the proceeding nodes in the tree.
	AuthenticateThing(thingID string, audience string, keyID string, key crypto.Signer, claims func() interface{}) Builder

	// RegisterThing with the ForgeRock Register Thing tree node. This node uses JWT PoP and requires a signed JWT
	// containing the thing's public key and key ID, along with a CA signed certificate that contains the same public
	// key. This method must be used along with the AuthenticateThing method as they share the same thing ID,
	// key and key ID. They do not share claims however. The JWT may include custom claims about the thing, which will
	// be added to the thing's identity on successful registration.
	RegisterThing(certificates []*x509.Certificate, claims func() interface{}) Builder

	// HandleCallbacksWith the supplied callback handlers when the thing is authenticated. The provided handlers must
	// match those configured in the AM authentication tree.
	HandleCallbacksWith(handlers ...callback.Handler) Builder

	// TimeoutRequestAfter sets the timeout on the communications between the Thing and AM or the Thing Gateway.
	TimeoutRequestAfter(time.Duration) Builder

	// Create a Thing instance and make an authentication request to AM. The callback handlers and information provided
	// in the AuthenticateThing and RegisterThing methods will be used to satisfy the callbacks received from the AM
	// authentication process.
	Create() (Thing, error)
}

// JWKThumbprint calculates the base64url-encoded JWK Thumbprint value for the given key.
// The thumbprint can be used for identifying or selecting the key.
// See https://tools.ietf.org/html/rfc7638.
func JWKThumbprint(key crypto.Signer) (string, error) {
	if key == nil {
		return "", jws.ErrMissingSigner
	}
	thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(thumbprint), nil
}
