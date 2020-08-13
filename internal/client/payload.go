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

import (
	"bytes"
	"encoding/json"

	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
)

// AMInfoResponse contains the information required to construct valid signed JWTs
type AMInfoResponse struct {
	Realm          string
	AccessTokenURL string
	AttributesURL  string
	ThingsVersion  string
}

// AuthenticatePayload represents the outbound and inbound data during an authentication request
type AuthenticatePayload struct {
	SessionToken
	AuthId    string              `json:"authId,omitempty"`
	AuthIDKey string              `json:"auth_id_digest,omitempty"`
	Callbacks []callback.Callback `json:"callbacks,omitempty"`
}

type GetAccessTokenPayload struct {
	Scope []string `json:"scope,omitempty"`
}

// SessionToken holds a session token
type SessionToken struct {
	TokenID string `json:"tokenId,omitempty"`
}

// ThingEndpointPayload wraps the payload destined for the Thing endpoint with the session token
type ThingEndpointPayload struct {
	Token   string `json:"token"`
	Payload string `json:"payload,omitempty"`
}

// IntrospectPayload contains an introspection request as defined by rfc7662
type IntrospectPayload struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

func (p GetAccessTokenPayload) String() string {
	return payloadToString(p)
}

// HasSessionToken returns true if the payload contains a session token
// Indicates that the authentication workflow has completed successfully
func (p AuthenticatePayload) HasSessionToken() bool {
	return p.TokenID != ""
}

func (p AuthenticatePayload) String() string {
	return payloadToString(p)
}

func payloadToString(p interface{}) string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "\t")
	if err != nil {
		return ""
	}
	return out.String()
}
