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
	"net/url"
	"time"

	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
)

// Session represents an authenticated session with AM.
type Session interface {

	// Token returns the session token.
	Token() string

	// Valid returns true if the session is valid.
	Valid() (bool, error)

	// Logout the session.
	Logout() error
}

type Builder interface {

	// ConnectTo the server at the given URL.
	// Supports http(s) for connecting to AM and coap(s) for connecting to the Thing Gateway.
	ConnectTo(url *url.URL) Builder

	// InRealm specifies the path to the AM realm in which to authenticate.
	// The realm is not required if connecting to the Thing Gateway. If provided it will be ignored.
	InRealm(realm string) Builder

	// WithTree sets the name of the AM authentication tree that will be used for authentication.
	// The tree is not required if connecting to the Thing Gateway. If provided it will be ignored.
	WithTree(tree string) Builder

	// AuthenticateWith the supplied callback handlers when creating the session. The provided handlers must
	// match those configured in the AM authentication tree.
	AuthenticateWith(handlers ...callback.Handler) Builder

	// TimeoutRequestAfter sets the timeout on the communications between the Thing and AM or the Thing Gateway.
	TimeoutRequestAfter(d time.Duration) Builder

	// Create a Session instance and make an authentication request to AM. The callback handlers provided
	// will be used to satisfy the callbacks received from the AM authentication process.
	Create() (Session, error)
}
