/*
 * Copyright 2021 ForgeRock AS
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
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"time"
)

var key jose.JSONWebKey

func handler(w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading body; %s", err), http.StatusBadRequest)
		return
	}
	log.Printf("Received:\n%s\n", string(data))

	b, _ := pem.Decode(data)
	var csr *x509.CertificateRequest
	if b == nil {
		csr, err = x509.ParseCertificateRequest(data)
	} else {
		csr, err = x509.ParseCertificateRequest(b.Bytes)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable body to parse into a x509 CSR; %s", err),
			http.StatusBadRequest)
		return
	}
	certBytes, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      csr.Subject,
			NotBefore:    time.Now().Add(-24 * time.Hour),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		},
		key.Certificates[0],
		csr.PublicKey,
		key.Key)
	if err != nil {
		http.Error(w, fmt.Sprintf("Unable create certificate x509 certificate; %s", err),
			http.StatusInternalServerError)
		return
	}

	log.Printf("Created certificate for %s\n", csr.Subject)
	w.Write(certBytes)
}

func main() {
	ec256TestBytes := []byte(`{"kty": "EC",
		"kid": "Fol7IpdKeLZmzKtCEgi1LDhSIzM=",
		"x": "N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA",
		"y": "uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c",
		"crv": "P-256",
		"alg": "ES256",
		"d": "w9rAMaNcP7cA0e5SECc4Tk1PDQEY66ml9y9-6E8fmR4",
		"x5c": ["MIIBwjCCAWkCCQCw3GyPBTSiGzAJBgcqhkjOPQQBMGoxCzAJBgNVBAYTAlVLMRAwDgYDVQQIEwdCcmlzdG9sMRAwDgYDVQQHEwdCcmlzdG9sMRIwEAYDVQQKEwlGb3JnZVJvY2sxDzANBgNVBAsTBk9wZW5BTTESMBAGA1UEAxMJZXMyNTZ0ZXN0MB4XDTE3MDIwMzA5MzQ0NloXDTIwMTAzMDA5MzQ0NlowajELMAkGA1UEBhMCVUsxEDAOBgNVBAgTB0JyaXN0b2wxEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEPMA0GA1UECxMGT3BlbkFNMRIwEAYDVQQDEwllczI1NnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3sy05tV/3YUlPBi9jZm9NVPeuBmntrtcO3NP/1HDsgLsTZsqKHD6KWIeJNRQnONcriWVaIcZYTKNykyCVUz93MAkGByqGSM49BAEDSAAwRQIgZhTox7WpCb9krZMyHfgCzHwfu0FVqaJsO2Nl2ArhCX0CIQC5GgWD5jjCRlIWSEFSDo4DZgoQFXaQkJUSUbJZYpi9dA=="]
	}`)
	if err := json.Unmarshal(ec256TestBytes, &key); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8088", nil))
}