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

// Package secrets provides a utility to read pre-created or dynamically create keys and certificates for Things.
// Only intended for examples and demos NOT production use.
package secrets

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const ec256Test = `{"kty": "EC",
	"kid": "Fol7IpdKeLZmzKtCEgi1LDhSIzM=",
    "x": "N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA",
	"y": "uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c",
	"crv": "P-256",
	"alg": "ES256",
	"d": "w9rAMaNcP7cA0e5SECc4Tk1PDQEY66ml9y9-6E8fmR4",
	"x5c": ["MIIBwjCCAWkCCQCw3GyPBTSiGzAJBgcqhkjOPQQBMGoxCzAJBgNVBAYTAlVLMRAwDgYDVQQIEwdCcmlzdG9sMRAwDgYDVQQHEwdCcmlzdG9sMRIwEAYDVQQKEwlGb3JnZVJvY2sxDzANBgNVBAsTBk9wZW5BTTESMBAGA1UEAxMJZXMyNTZ0ZXN0MB4XDTE3MDIwMzA5MzQ0NloXDTIwMTAzMDA5MzQ0NlowajELMAkGA1UEBhMCVUsxEDAOBgNVBAgTB0JyaXN0b2wxEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEPMA0GA1UECxMGT3BlbkFNMRIwEAYDVQQDEwllczI1NnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3sy05tV/3YUlPBi9jZm9NVPeuBmntrtcO3NP/1HDsgLsTZsqKHD6KWIeJNRQnONcriWVaIcZYTKNykyCVUz93MAkGByqGSM49BAEDSAAwRQIgZhTox7WpCb9krZMyHfgCzHwfu0FVqaJsO2Nl2ArhCX0CIQC5GgWD5jjCRlIWSEFSDo4DZgoQFXaQkJUSUbJZYpi9dA=="]
}`

var maxSerialNumber = new(big.Int).Exp(big.NewInt(2), big.NewInt(159), nil)

// Store for keys and certificates for Things
type Store struct {
	Path        string // location of key store on disk
	caJWK       *jose.JSONWebKey
	currentTime time.Time
}

// filepath returns the location of key store on disk. Defaults to ".secrets".
func (s *Store) filepath() string {
	if s.Path != "" {
		return s.Path
	}
	return ".secrets"
}

// read the key set from disc.
func (s *Store) read() (keySet jose.JSONWebKeySet, err error) {
	keySetBytes, err := os.ReadFile(s.filepath())
	switch {
	case err == nil:
		err = json.Unmarshal(keySetBytes, &keySet)
	case os.IsNotExist(err):
		// this is okay, when the key set is written to disk and store will be created
		err = nil
	}
	return keySet, err
}

// write the key set to disk.
// If the key set file does not exist, a new file is created. Otherwise, the existing file contents is replaced.
func (s *Store) write(keySet jose.JSONWebKeySet) error {
	b, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filepath(), b, 0644)
}

// certificateAuthority returns the CA JWK.
// If the CA has not been explicitly set, the ec256Test key is returned by default.
func (s *Store) certificateAuthority() (*jose.JSONWebKey, error) {
	if s.caJWK != nil {
		fmt.Println("return non-default ca")
		return s.caJWK, nil
	}

	ec256TestBytes := []byte(ec256Test)
	var key jose.JSONWebKey
	err := json.Unmarshal(ec256TestBytes, &key)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (s *Store) now() time.Time {
	if s.currentTime.IsZero() {
		return time.Now()
	}
	return s.currentTime
}

// Signer returns a signer associated with the given Key ID.
// If the store does not contain a JWK for that Key ID, a key is created and written to the store.
func (s *Store) Signer(kid string) (crypto.Signer, error) {
	keySet, err := s.read()
	if err != nil {
		return nil, err
	}

	keys := keySet.Key(kid)
	if len(keys) != 0 {
		signer, ok := keys[0].Key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key associated with %s is not a signer", kid)
		}
		return signer, nil
	}

	// create a key
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keySet.Keys = append(keySet.Keys,
		jose.JSONWebKey{KeyID: kid, Key: newKey, Algorithm: string(jose.ES256), Use: "sig"})

	err = s.write(keySet)
	if err != nil {
		return nil, err
	}
	return newKey, nil
}

// Certificates returns the certificates associated with the given Key ID.
// If the store does not contain a JWK for that Key ID, a key is created and written to the store.
// If the store does not contain one or more certificates for that Key ID, a certificate is created using the CA
// certificate held within the store. Dynamic certificates are created anew each time and are not stored.
func (s *Store) Certificates(thingID string) ([]*x509.Certificate, error) {
	keySet, err := s.read()
	if err != nil {
		return nil, err
	}

	keys := keySet.Key(thingID)
	if len(keys) != 0 && len(keys[0].Certificates) > 0 {
		return keys[0].Certificates, nil
	}

	caWebKey, err := s.certificateAuthority()
	if err != nil {
		return nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, err
	}
	signer, err := s.Signer(thingID)
	if err != nil {
		return nil, err
	}
	cert, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{CommonName: thingID},
			NotBefore:    s.now().Add(-24 * time.Hour),
			NotAfter:     s.now().Add(24 * time.Hour),
		},
		caWebKey.Certificates[0],
		signer.Public(),
		caWebKey.Key)
	if err != nil {
		return nil, err
	}
	certificates, err := x509.ParseCertificates(cert)
	if err != nil {
		return nil, err
	}
	return certificates, nil
}

// SetCertificateAuthority sets the CA certificate used by the store to create dynamic certificates.
func (s *Store) SetCertificateAuthority(jwk *jose.JSONWebKey) {
	s.caJWK = jwk
}
