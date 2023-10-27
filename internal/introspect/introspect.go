/*
 * Copyright 2020-2023 ForgeRock AS
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

package introspect

import (
	"encoding/json"
	"strings"

	"github.com/ForgeRock/iot-edge/v7/internal/clock"
)

const Skew int64 = 60

// InactiveIntrospectionBytes contains the standard introspection for an inactive token
var InactiveIntrospectionBytes = []byte(`{"active":false}`)

// IsActive returns true if the given introspection bytes indicate that the token is active
func IsActive(b []byte) bool {
	introspection := struct {
		Active bool `json:"active"`
	}{}
	if err := json.Unmarshal(b, &introspection); err != nil {
		return false
	}
	return introspection.Active
}

// CreateFromJWT converts a valid JWT access token into an active token introspection.
func CreateFromJWT(b []byte) ([]byte, error) {
	var claims map[string]interface{}
	err := json.Unmarshal(b, &claims)
	if err != nil {
		return b, err
	}
	if _, ok := claims["scope"]; ok {
		// extract the scope array and convert to space-separated string
		var scopeContainer struct {
			Scope []string `json:"scope"`
		}
		err = json.Unmarshal(b, &scopeContainer)
		if err != nil {
			return b, err
		}
		claims["scope"] = strings.Join(scopeContainer.Scope, " ")
	}

	claims["active"] = true
	return json.Marshal(claims)
}

type timeClaims struct {
	Exp int64 `json:"exp"`
	Nbf int64 `json:"nbf"`
}

// ValidNow returns true if the expired and not before claims indicate that the token is valid for the current local
// time. From RFC7519:
//
//	processing of the "exp" claim requires that the current date/time
//	MUST be before the expiration date/time listed in the "exp" claim
//	processing of the "nbf" claim requires that the current date/time
//	MUST be after or equal to listed in the "nbf" claim
func ValidNow(b []byte) bool {
	var claims timeClaims
	if err := json.Unmarshal(b, &claims); err != nil {
		return false
	}
	now := clock.Clock().Unix()
	return now < (claims.Exp+Skew) && now >= (claims.Nbf-Skew)
}
