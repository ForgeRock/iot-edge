/*
 * Copyright 2020-2021 ForgeRock AS
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

package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/ForgeRock/iot-edge/v7/internal/jws"
)

// PublicKeyCertificate returns a stripped down tls certificate containing the public key
func PublicKeyCertificate(key crypto.Signer) (cert tls.Certificate, err error) {
	if key == nil {
		return cert, jws.ErrMissingSigner
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

// ParsePEM parse a PEM block into a crypto signer
// EC and RSA private keys encoded in unencrypted PKCS1 or PKCS8 format are supported.
func ParsePEM(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		s, ok := privateKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("unable to cast to a signer")
		}
		return s, nil
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported type '%s'", block.Type)
	}
}
