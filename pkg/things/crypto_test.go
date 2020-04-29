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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"gopkg.in/square/go-jose.v2"
	"testing"
)

var (
	es256Key, _      = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	es384Key, _      = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	es512Key, _      = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	_, eddsaKey, err = ed25519.GenerateKey(rand.Reader)
	rsa256Key, _     = rsa.GenerateKey(rand.Reader, 2048)
	rsa384Key, _     = rsa.GenerateKey(rand.Reader, 3072)
	rsa512Key, _     = rsa.GenerateKey(rand.Reader, 4096)
)

func TestSigningJWKAlgorithmFromKey(t *testing.T) {
	tests := []struct {
		name   string
		signer crypto.Signer
		alg    jose.SignatureAlgorithm
		err    error
	}{
		{name: "missing-signer", signer: nil, err: errMissingSigner},
		{name: "unsupported-algorithm", signer: testBadSigner{}, err: errUnsupportedSigningAlgorithm},
		{name: "es256-key", signer: es256Key, alg: jose.ES256},
		{name: "es384-key", signer: es384Key, alg: jose.ES384},
		{name: "es521-key", signer: es512Key, alg: jose.ES512},
		{name: "eddsa-key", signer: eddsaKey, alg: jose.EdDSA},
		{name: "rsa256-key", signer: rsa256Key, alg: jose.PS256},
		{name: "rsa384-key", signer: rsa384Key, alg: jose.PS384},
		{name: "rsa512-key", signer: rsa512Key, alg: jose.PS512},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			alg, err := signingJWKAlgorithmFromKey(subtest.signer)
			if err != subtest.err || alg != subtest.alg {
				t.Errorf("Expected %s,%s; got %s, %s", subtest.alg, subtest.err, alg, err)
			}
		})
	}
}
