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
	"github.com/ForgeRock/iot-edge/internal/debug"
	"github.com/ForgeRock/iot-edge/internal/jws"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"gopkg.in/square/go-jose.v2"
	"log"
	"net/url"
	"time"
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

	// RequestAttributes requests the attributes with the specified names associated with the thing's identity.
	// If no names are specified then all the allowed attributes will be returned.
	RequestAttributes(names ...string) (response AttributesResponse, err error)

	// Logout will invalidate the thing's session with AM. It is good practice to log out if the thing will not make
	// new requests for a prolonged period. Once logged out the thing will automatically create a new session when a
	// new request is made.
	Logout() error
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
	Create() (Thing, error)
}

// JWKThumbprint calculates the base64url-encoded JWK Thumbprint value for the given key.
// The thumbprint can be used for identifying or selecting the key.
// See https://tools.ietf.org/html/rfc7638
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
