/*
 * Copyright 2022-23 ForgeRock AS
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

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"net/url"
	"os"
)

type csrHandler struct {
	thingID string
	signer  crypto.PrivateKey
}

func (a csrHandler) Handle(cb callback.Callback) (bool, error) {
	if cb.Type == callback.TypeHiddenValueCallback && cb.ID() != "csr" {
		return false, nil
	}
	csrPem := certificateSigningRequest(a.thingID, a.signer)
	cb.Input[0].Value = csrPem
	return true, nil
}

func certificateSigningRequest(thingID string, signer crypto.PrivateKey) string {
	thingCSRTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         thingID,
			Country:            []string{"GB"},
			Locality:           []string{"Bristol"},
			Organization:       []string{"ForgeRock"},
			OrganizationalUnit: []string{"Engineering"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, thingCSRTemplate, signer)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	csrPem := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	return csrPem
}

func register(tree string, deviceID string, amURL *url.URL, keyID string, signer crypto.Signer) thing.Thing {
	fmt.Println("--> Register & Authenticate", deviceID)
	device, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree(tree).
		AuthenticateThing(deviceID, "/", keyID, signer, nil).
		HandleCallbacksWith(
			callback.ProofOfPossessionHandler(deviceID, "/", keyID, signer),
			csrHandler{deviceID, signer}).
		Create()
	if err != nil {
		fmt.Println("Registration & Authentication failed", "\nReason: ", err)
		os.Exit(1)
	}
	fmt.Println("--> Registered & Authenticated successfully")
	return device
}

func authenticate(tree string, deviceID string, amURL *url.URL, keyID string, signer crypto.Signer) thing.Thing {
	fmt.Println("--> Authenticate", deviceID)
	device, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree(tree).
		AuthenticateThing(deviceID, "/", keyID, signer, nil).
		HandleCallbacksWith(
			csrHandler{deviceID, signer}).
		Create()
	if err != nil {
		fmt.Println("Authentication failed", "\nReason: ", err)
		os.Exit(1)
	}
	fmt.Println("--> Authenticated successfully")
	return device
}

func requestCertificate(device thing.Thing) {
	fmt.Println("--> Requesting x.509 Certificate")
	certResponse, err := device.RequestAttributes("thingCertificatePem")
	certString, err := certResponse.GetFirst("thingCertificatePem")
	if err != nil {
		fmt.Println(certResponse.Content)
		fmt.Println("request attributes failed", err)
		os.Exit(1)
	}

	block, _ := pem.Decode([]byte(certString))
	if block == nil {
		fmt.Println("Failed to parse PEM")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate", err)
		os.Exit(1)
	}
	fmt.Println("== x.509 Certificate ==",
		"\nSubject:", cert.Subject,
		"\nIssuer:", cert.Issuer,
		"\nSerial Number:", cert.SerialNumber,
		"\nValidity:", "\n\tNot Before:", cert.NotBefore, "\n\tNot After: ", cert.NotAfter)
}

func registerThings(tree string) {
	deviceID := "Device-8456232771"
	amURL, _ := url.Parse(os.Getenv("AM_URL"))
	store := secrets.Store{}
	thingKey, err := store.Signer(deviceID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	thingKid, _ := thing.JWKThumbprint(thingKey)

	fmt.Println("\nPress Enter to register and authenticate...")
	fmt.Scanln()
	device := register(tree, deviceID, amURL, thingKid, thingKey)

	fmt.Println("\nPress Enter to request the certificate...")
	fmt.Scanln()
	requestCertificate(device)

	fmt.Println("\nPress Enter to re-authenticate and request the certificate...")
	fmt.Scanln()
	device = authenticate(tree, deviceID, amURL, thingKid, thingKey)
	requestCertificate(device)
}

func main() {
	//thing.SetDebugLogger(log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Llongfile))

	tree := os.Getenv("TREE")
	registerThings(tree)
}
