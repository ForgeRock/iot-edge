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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"gopkg.in/square/go-jose.v2"
	"math/big"
)

var (
	errMissingSigner               = errors.New("missing signer")
	errUnsupportedSigningAlgorithm = errors.New("unsupported algorithm")
)

// signingJWAFromKey attempts to deduce the signing algorithm by looking at the public key
func signingJWAFromKey(s crypto.Signer) (alg jose.SignatureAlgorithm, err error) {
	if s == nil {
		return alg, errMissingSigner
	}
	switch k := s.Public().(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		}
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	case *rsa.PublicKey:
		switch k.N.BitLen() / 8 {
		case 256:
			return jose.PS256, nil
		case 384:
			return jose.PS384, nil
		case 512:
			return jose.PS512, nil
		}
	}
	return alg, errUnsupportedSigningAlgorithm
}

// publicKeyCertificate returns a stripped down tls certificate containing the public key
func publicKeyCertificate(key crypto.Signer) (cert tls.Certificate, err error) {
	if key == nil {
		return cert, errMissingSigner
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return cert, err
	}
	return tls.Certificate{

		Certificate: [][]byte{raw},
		PrivateKey:  key,
		Leaf:        &template,
	}, nil
}
