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
	"gopkg.in/square/go-jose.v2/cryptosigner"
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

// pssOpaqueSigner implements the jose.OpaqueSigner interface for PSS signature keys
// Similar to the crytosigner.Opaque implementation for PSS keys except different salt lengths are used
type pssOpaqueSigner struct {
	alg    jose.SignatureAlgorithm
	signer crypto.Signer
}

func (r pssOpaqueSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: r.signer.Public()}
}

func (r pssOpaqueSigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{r.alg}
}

func (r pssOpaqueSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	var hash crypto.Hash
	switch alg {
	case jose.PS256:
		hash = crypto.SHA256
	case jose.PS384:
		hash = crypto.SHA384
	case jose.PS512:
		hash = crypto.SHA512
	default:
		return nil, jose.ErrUnsupportedAlgorithm
	}

	var hashed []byte
	if hash != crypto.Hash(0) {
		hasher := hash.New()
		if _, err := hasher.Write(payload); err != nil {
			return nil, err
		}
		hashed = hasher.Sum(nil)
	}
	return r.signer.Sign(rand.Reader, hashed, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       hash,
	})
}

// newJOSESigner creates a new JOSE signer from the crypto signer
func newJOSESigner(key crypto.Signer, opts *jose.SignerOptions) (jose.Signer, error) {
	// check that the signer is supported
	alg, err := signingJWAFromKey(key)
	if err != nil {
		return nil, err
	}

	var opaque jose.OpaqueSigner
	switch alg {
	case jose.PS256, jose.PS384, jose.PS512:
		opaque = pssOpaqueSigner{alg: alg, signer: key}
	default:
		opaque = cryptosigner.Opaque(key)
	}
	return jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
}
