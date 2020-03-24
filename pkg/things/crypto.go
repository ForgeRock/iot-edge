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
	"crypto/ecdsa"
	"errors"

	"gopkg.in/square/go-jose.v2"
)

// signatureAlgorithm attempts to deduce the signing algorithm by looking at the public key
func signatureAlgorithm(s crypto.Signer) (alg jose.SignatureAlgorithm, err error) {
	if s == nil {
		return alg, errors.New("no signer")
	}
	switch k := s.Public().(type) {
	case *ecdsa.PublicKey:
		if k.Curve.Params().Name == "P-256" {
			return jose.ES256, nil
		}
	}
	return alg, errors.New("unsupported algorithm")
}
