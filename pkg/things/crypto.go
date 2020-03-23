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
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"gopkg.in/square/go-jose.v2"
)

// joseECDSASigner wraps a crypto.Signer so that it implements the jose.OpaqueSigner interface
type joseECDSASigner struct {
	signer crypto.Signer
	alg    jose.SignatureAlgorithm
}

// Public returns the public key of the current signing key.
func (s joseECDSASigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{KeyID: "pop.cnf", Key: s.signer.Public(), Algorithm: string(s.alg), Use: "sig"}
}

// Algs returns a list of supported signing algorithms.
func (s joseECDSASigner) Algs() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// SignPayload hashes and signs a payload
func (s joseECDSASigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	if alg != jose.ES256 {
		return nil, fmt.Errorf("unsupported algorithm %v", alg)
	}
	digest := sha256.Sum256(payload)
	b, err := s.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	// ECDSA sign returns the signature ans1 encoded.
	// AM expects that the signature is 2*keyBytes long
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(b, &sig)
	if err != nil {
		return nil, err
	}
	keyBytes := 32
	rBytes := sig.R.Bytes()
	rBytesPadded := make([]byte, keyBytes)
	copy(rBytesPadded[keyBytes-len(rBytes):], rBytes)

	sBytes := sig.S.Bytes()
	sBytesPadded := make([]byte, keyBytes)
	copy(sBytesPadded[keyBytes-len(sBytes):], sBytes)

	return append(rBytesPadded, sBytesPadded...), nil
}

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
