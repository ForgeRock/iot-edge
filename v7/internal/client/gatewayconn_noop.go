// +build http,!coap

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

package client

import "errors"

var errCOAPNotBuilt = errors.New("coap(s) scheme is unsupported")

func (c *gatewayConnection) Initialise() error {
	return errCOAPNotBuilt
}

func (c *gatewayConnection) Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
	return reply, errCOAPNotBuilt
}

func (c *gatewayConnection) AMInfo() (info AMInfoResponse, err error) {
	return info, errCOAPNotBuilt
}

func (c *gatewayConnection) ValidateSession(tokenID string) (ok bool, err error) {
	return ok, errCOAPNotBuilt
}

func (c *gatewayConnection) LogoutSession(tokenID string) (err error) {
	return errCOAPNotBuilt
}

func (c *gatewayConnection) AccessToken(tokenID string, content ContentType, payload string) (reply []byte, err error) {
	return reply, errCOAPNotBuilt
}

func (c *gatewayConnection) IntrospectAccessToken(token string) (introspection []byte, err error) {
	return introspection, errCOAPNotBuilt
}

func (c *gatewayConnection) Attributes(tokenID string, content ContentType, payload string, names []string) (reply []byte, err error) {
	return reply, errCOAPNotBuilt
}
