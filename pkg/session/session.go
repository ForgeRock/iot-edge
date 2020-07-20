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
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"net/url"
	"time"
)

// Session holds session data
type Session interface {

	// Token returns the session token
	Token() string

	// HasRestrictedToken returns true if the session has a restricted token
	HasRestrictedToken() bool

	// SigningKey returns the signing key associated with a restricted SSO token
	SigningKey() crypto.Signer

	// Nonce returns the session nonce
	Nonce() int

	// IncrementNonce increments the session nonce
	IncrementNonce()

	// Valid returns true if the session is valid
	Valid() (bool, error)

	// Logout the session
	Logout() error
}

type Builder interface {
	ConnectTo(url *url.URL) Builder

	InRealm(realm string) Builder

	WithTree(tree string) Builder

	AuthenticateWith(handlers ...callback.Handler) Builder

	TimeoutRequestAfter(d time.Duration) Builder

	Create() (Session, error)
}
