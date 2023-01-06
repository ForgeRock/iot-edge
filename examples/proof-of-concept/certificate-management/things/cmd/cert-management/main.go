/*
 * Copyright 2022 ForgeRock AS
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	"encoding/pem"
	"net/url"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

type csrHandler struct {
	thingID string
	signer  crypto.PrivateKey
}

func handlerMatch(cb callback.Callback, outputName string) bool {
	if cb.Type != "StringAttributeInputCallback" {
		return false
	}
	name := ""
	for _, e := range cb.Output {
		if e.Name == "name" {
			name = e.Value.(string)
			break
		}
	}
	if name != outputName {
		return false
	}
	return true
}

func (a csrHandler) Handle(cb callback.Callback) (bool, error) {
	if !handlerMatch(cb, "thingProperties") {
		return false, nil
	}
	for i, e := range cb.Input {
		if ok, _ := regexp.MatchString(`IDToken\d+`, e.Name); ok {
			csrPem := certificateSigningRequest(a.thingID, a.signer)
			thingProperties, err := json.Marshal(struct {
				CSR string `json:"csr"`
			}{
				CSR: csrPem,
			})
			if err != nil {
				return false, err
			}
			cb.Input[i].Value = base64.StdEncoding.EncodeToString(thingProperties)
			fmt.Println("--> Providing CSR =", cb.Input[i].Value)
			return true, nil
		}
	}
	return false, nil
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

func register(deviceID string, amURL *url.URL, keyID string, signer crypto.Signer) thing.Thing {
	fmt.Println("--> Register & Authenticate", deviceID)
	device, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
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

func authenticate(deviceID string, amURL *url.URL, keyID string, signer crypto.Signer) thing.Thing {
	fmt.Println("--> Authenticate", deviceID)
	device, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
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
	configResponse, _ := device.RequestAttributes("thingConfig")
	configString, _ := configResponse.GetFirst("thingConfig")
	configJson := struct {
		Cert string `json:"cert"`
	}{}
	err := json.Unmarshal([]byte(configString), &configJson)
	if err != nil {
		fmt.Println("failed to parse config")
		os.Exit(1)
	}
	block, _ := pem.Decode([]byte(configJson.Cert))
	if block == nil {
		fmt.Println("failed to parse PEM")
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("failed to parse certificate", err)
		os.Exit(1)
	}
	fmt.Println("== x.509 Certificate ==",
		"\nSubject:", cert.Subject,
		"\nIssuer:", cert.Issuer,
		"\nSerial Number:", cert.SerialNumber,
		"\nValidity:", "\n\tNot Before:", cert.NotBefore, "\n\tNot After: ", cert.NotAfter)
}

func main() {
	//thing.SetDebugLogger(log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Llongfile))
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
	device := register(deviceID, amURL, thingKid, thingKey)

	fmt.Println("\nPress Enter to request the certificate...")
	fmt.Scanln()
	requestCertificate(device)

	fmt.Println("\nPress Enter to re-authenticate and request the certificate...")
	fmt.Scanln()
	device = authenticate(deviceID, amURL, thingKid, thingKey)
	requestCertificate(device)
}
