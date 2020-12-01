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

package secrets

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
)

func copyFile(dest, src string) error {
	b, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dest, b, 0666)
}

func TestStore_DefaultPath(t *testing.T) {
	store := &Store{}
	_, err := store.Signer(uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(".secrets"); err != nil {
		t.Fatal(err)
	}
	os.Remove(".secrets")
}

func TestStore_Signer(t *testing.T) {
	// copy reference secrets
	preexisting := "dopey.secrets"
	notYetCreated := "happy.secrets"
	if err := copyFile(preexisting, "testdata/secrets"); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(preexisting)
	defer os.Remove(notYetCreated)

	var knownKey jose.JSONWebKey
	err := json.Unmarshal(
		[]byte(`{"use":"sig","kty":"EC","kid":"572ddcde-1532-4175-861b-0622ac2f3bf3","crv":"P-256","alg":"ES256","x":"J4myf5y8cpKubDrit6RLnF3FAf__VMjZzdIFMF9yv3M","y":"6eX5cj0oVhiLSpzTgvqtZHjp7IBr4aIO5Jl_KfNnq4c","d":"jyWleC86wyd0PppZTySEb8NK7AtaJe9Xol8uqQ0gBZQ"}`),
		&knownKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		keyStorePath string
		thingID      string
		expectedKey  *ecdsa.PrivateKey
	}{
		{name: "known-thing", keyStorePath: preexisting, thingID: "572ddcde-1532-4175-861b-0622ac2f3bf3", expectedKey: knownKey.Key.(*ecdsa.PrivateKey)},
		{name: "unknown-thing", keyStorePath: preexisting, thingID: uuid.New().String()},
		{name: "not-yet-created-store", keyStorePath: notYetCreated, thingID: uuid.New().String()},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			store := &Store{Path: subtest.keyStorePath}
			signer, err := store.Signer(subtest.thingID)
			if err != nil {
				t.Fatal(err)
			}
			checkKey := subtest.expectedKey
			if checkKey == nil {
				fmt.Println("creating new key")
				key2, err := store.Signer(subtest.thingID)
				if err != nil {
					t.Fatal(err)
				}
				checkKey = key2.(*ecdsa.PrivateKey)

			}
			if !signer.(*ecdsa.PrivateKey).Equal(checkKey) {
				t.Error("keys do not match")
			}
		})
	}
}

func TestStore_Certificate(t *testing.T) {
	preexisting := "sneezy.secrets"
	notYetCreated := "sleepy.secrets"
	if err := copyFile(preexisting, "testdata/secrets"); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(preexisting)
	defer os.Remove(notYetCreated)

	tests := []struct {
		name         string
		keyStorePath string
		thingID      string
		expectedCert string
	}{
		{name: "known-thing-with-cert", keyStorePath: preexisting, thingID: "4e645215-49e9-401a-91c9-ac43f1d03326",
			expectedCert: "MIIBnTCCAUOgAwIBAgIUcDNylZ0B3eG0SLk/KSfUNu5KsdwwCgYIKoZIzj0EAwIwajELMAkGA1UEBhMCVUsxEDAOBgNVBAgTB0JyaXN0b2wxEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEPMA0GA1UECxMGT3BlbkFNMRIwEAYDVQQDEwllczI1NnRlc3QwHhcNMjAxMTI1MTcyNzExWhcNMzAxMTIzMTcyNzExWjAvMS0wKwYDVQQDEyQ0ZTY0NTIxNS00OWU5LTQwMWEtOTFjOS1hYzQzZjFkMDMzMjYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQLFDEdCMsCag6KLIajH2bCXjL3CQug3q5ZX4AslHEMhkipIfsCUcVJVZjajpZ3C39myfeaNMDsWfhRzNIQefJ+owIwADAKBggqhkjOPQQDAgNIADBFAiEAz8PIPsCpBpyfEiifQIr9jtxGO1eMgEqoa8E6VfASvdcCIGuylJcK6qxhMId1RMs62r+w824obPtB5REMGqnJ/wXe"},
		{name: "known-thing-no-cert", keyStorePath: preexisting, thingID: "572ddcde-1532-4175-861b-0622ac2f3bf3"},
		{name: "unknown-thing", keyStorePath: preexisting, thingID: uuid.New().String()},
		{name: "not-yet-created-store", keyStorePath: notYetCreated, thingID: uuid.New().String()},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			store := &Store{Path: subtest.keyStorePath}
			cert, err := store.Certificates(subtest.thingID)
			if err != nil {
				t.Fatal(err)
			}
			if len(cert) == 0 {
				t.Fatal("certificate array is empty")
			}
			if subtest.expectedCert != "" {
				b, err := base64.StdEncoding.DecodeString(subtest.expectedCert)
				if err != nil {
					t.Fatal(err)
				}
				expectedCert, err := x509.ParseCertificate(b)
				if err != nil {
					t.Fatal(err)
				}
				if !cert[0].Equal(expectedCert) {
					t.Error("certificates do not match")
				}
			}
		})
	}
}

func createDummyCA(currentTime time.Time) (*jose.JSONWebKey, error) {
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	templateCert :=
		&x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{CommonName: "ca"},
			NotBefore:    currentTime.Add(-24 * time.Hour),
			NotAfter:     currentTime.Add(24 * time.Hour),
			IsCA: true,
			KeyUsage: x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		}
	caBytes, err := x509.CreateCertificate(rand.Reader,
		templateCert,
		templateCert,
		caKey.Public(),
		caKey,
	)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{KeyID: "ca", Key: caKey, Algorithm: string(jose.ES256), Use: "sig", Certificates: []*x509.Certificate{caCert}}, nil
}

func TestStore_SetCertificateAuthority(t *testing.T) {
	notYetCreated := "grumpy.secrets"
	defer os.Remove(notYetCreated)

	// change current time when the ec256Test certificate is updated
	currentTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	ca, err := createDummyCA(currentTime)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name         string
		keyStorePath string
		thingID      string
		ca           *jose.JSONWebKey
	}{
		{name: "default-ca", keyStorePath: notYetCreated, thingID: uuid.New().String()},
		{name: "non-default-ca", keyStorePath: notYetCreated, thingID: uuid.New().String(), ca: ca},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			store := &Store{Path: subtest.keyStorePath, currentTime: currentTime}
			if subtest.ca != nil {
				store.SetCertificateAuthority(subtest.ca)
			}
			cert, err := store.Certificates(subtest.thingID)
			if err != nil {
				t.Fatal(err)
			}
			if len(cert) == 0 {
				t.Fatal("certificate array is empty")
			}

			ca := subtest.ca
			if ca == nil {
				err = json.Unmarshal([]byte(ec256Test), &ca)
				if err != nil {
					log.Fatal(err)
				}
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca.Certificates[0])

			opts := x509.VerifyOptions{
				Roots:       roots,
				CurrentTime: currentTime,
			}

			if _, err := cert[0].Verify(opts); err != nil {
				t.Fatal(err)
			}

		})
	}
}
