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

package anvil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"

	"github.com/go-jose/go-jose/v3"
)

var (
	es256 *ecdsa.PrivateKey
	es384 *ecdsa.PrivateKey
	es512 *ecdsa.PrivateKey
	ed    ed25519.PrivateKey
	ps256 *rsa.PrivateKey
	ps384 *rsa.PrivateKey
	ps512 *rsa.PrivateKey
)

func init() {
	var err error
	es256, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	es384, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	es512, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}

	_, ed, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	ps256, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	ps384, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}

	ps512, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}
}

// ConfirmationKey returns a key for signing requests to AM that is accompanied by a restricted PoP SSO token.
func ConfirmationKey(algorithm jose.SignatureAlgorithm) (public jose.JSONWebKeySet, private SigningKey, err error) {
	// create a new key
	switch algorithm {
	case jose.ES256:
		private.Signer = es256
	case jose.ES384:
		private.Signer = es384
	case jose.ES512:
		private.Signer = es512
	case jose.EdDSA:
		private.Signer = ed
	case jose.PS256:
		private.Signer = ps256
	case jose.PS384:
		private.Signer = ps384
	case jose.PS512:
		private.Signer = ps512
	default:
		return public, private, fmt.Errorf("unsupported signing algorithm %s", algorithm)
	}

	webKey := jose.JSONWebKey{Key: private.Signer.Public(), Algorithm: string(algorithm), Use: "sig"}
	kid, err := webKey.Thumbprint(crypto.SHA256)
	if err != nil {
		return public, private, err
	}
	webKey.KeyID = base64.URLEncoding.EncodeToString(kid)
	private.KID = webKey.KeyID
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{webKey}}, private, nil
}

// SigningKey describes a key used for signing messages sent to AM
type SigningKey struct {
	KID    string
	Signer crypto.Signer
}
