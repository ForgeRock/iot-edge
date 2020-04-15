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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// sendCommandClaims defines the claims expected in the signed JWT provided with a Send Command request
type sendCommandClaims struct {
	CSRF string `json:"csrf"`
}

// extractJWTPayload parses a signed JWT and unmarshals the payload into the supplied claims
// The signature is NOT checked so these claims are unverified.
// This function exists because the JOSE library fails when parsing a signed token with a non-string nonce,
// AM requires an integer nonce
func extractJWTPayload(token string, claims interface{}) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("unexpected serialisation")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, claims)
}
