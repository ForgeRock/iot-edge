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

package anvil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	jose "gopkg.in/square/go-jose.v2"
)

// GenerateConfirmationKey generates a key for signing requests to AM that is accompanied by a restricted PoP SSO token.
func GenerateConfirmationKey() (public jose.JSONWebKeySet, private crypto.Signer, err error) {
	// create a new key
	private, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: "pop.cnf", Key: private.Public(), Algorithm: string(jose.ES256), Use: "sig"}},
	}, private, err
}
