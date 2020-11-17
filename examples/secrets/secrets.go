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
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log"
	"math/big"
	"time"

	"gopkg.in/square/go-jose.v2"
)

var keyStore = "{\"keys\":[" +
	"{\"use\":\"sig\"," +
	"\"kty\":\"EC\"," +
	"\"kid\":\"572ddcde-1532-4175-861b-0622ac2f3bf3\"," +
	"\"crv\":\"P-256\"," +
	"\"alg\":\"ES256\"," +
	"\"x\":\"J4myf5y8cpKubDrit6RLnF3FAf__VMjZzdIFMF9yv3M\"," +
	"\"y\":\"6eX5cj0oVhiLSpzTgvqtZHjp7IBr4aIO5Jl_KfNnq4c\"," +
	"\"d\":\"jyWleC86wyd0PppZTySEb8NK7AtaJe9Xol8uqQ0gBZQ\"}," +
	"{\"use\":\"sig\"," +
	"\"kty\":\"EC\"," +
	"\"kid\":\"d21f083f-c6a1-4ae7-94a4-e2604bb25e1d\"," +
	"\"crv\":\"P-256\"," +
	"\"alg\":\"ES256\"," +
	"\"x\":\"05-ue0KZ15MAoR4iSkPXePLBpelIFwNy4yWQF-1MLSA\"," +
	"\"y\":\"v4kX8AhvY990LZLsIfwaPyKsGCsqAc05k5-9Z325hB4\"," +
	"\"d\":\"2bX0-tNfO2fwTANLUeje9_NoF1IETmMqJsEjBw6Pens\"}," +
	"{\"use\":\"sig\"," +
	"\"kty\":\"EC\"," +
	"\"kid\":\"47cf707c-80c1-4816-b067-99db2a443113\"," +
	"\"crv\":\"P-256\"," +
	"\"alg\":\"ES256\"," +
	"\"x\":\"6cS0SXSsILpyzSi6DgLL2qKZIRsgkmUaus6qfzWl7Ek\"," +
	"\"y\":\"x-tUNJOcD2AVULh19d1eLNsjCqIX-uHJ0cWdw_WPZss\"," +
	"\"d\":\"EgRndTr2jv4rv_rAHPiziL-Q8nm523cZCwS5UPIMGVk\"}," +
	"{\"use\":\"sig\"," +
	"\"kty\":\"EC\"," +
	"\"kid\":\"9c753fa7-68a3-418a-9571-e0eda88b1617\"," +
	"\"crv\":\"P-256\"," +
	"\"alg\":\"ES256\"," +
	"\"x\":\"KCCUz_tv2swnOwytUCi6yIbyx22w_xjqWAypob61vJE\"," +
	"\"y\":\"RT8XY1HCIso3HoUif9oBpwee2CBfjouqf2JjtFT6lKs\"," +
	"\"d\":\"Fulx_Vjc-jRmYP_0K6TVFoIuK9MEYOgHCXRxCe3LZkY\"}]}"

var maxSerialNumber = new(big.Int).Exp(big.NewInt(2), big.NewInt(159), nil)

func caSigningKey() *jose.JSONWebKey {
	ec256TestBytes := []byte("{\"kty\": \"EC\"," +
		"\"kid\": \"Fol7IpdKeLZmzKtCEgi1LDhSIzM=\"," +
		"\"x\": \"N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA\"," +
		"\"y\": \"uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c\"," +
		"\"crv\": \"P-256\"," +
		"\"alg\": \"ES256\"," +
		"\"d\": \"w9rAMaNcP7cA0e5SECc4Tk1PDQEY66ml9y9-6E8fmR4\"," +
		"\"x5c\": [\"MIIBwjCCAWkCCQCw3GyPBTSiGzAJBgcqhkjOPQQBMGoxCzAJBgNVBAYTAlVLMRAwDgYDVQQIEwdCcmlzdG9sMRAwDgYDV" +
		"QQHEwdCcmlzdG9sMRIwEAYDVQQKEwlGb3JnZVJvY2sxDzANBgNVBAsTBk9wZW5BTTESMBAGA1UEAxMJZXMyNTZ0ZXN0MB4XDTE3MDIwMz" +
		"A5MzQ0NloXDTIwMTAzMDA5MzQ0NlowajELMAkGA1UEBhMCVUsxEDAOBgNVBAgTB0JyaXN0b2wxEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgN" +
		"VBAoTCUZvcmdlUm9jazEPMA0GA1UECxMGT3BlbkFNMRIwEAYDVQQDEwllczI1NnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3" +
		"sy05tV/3YUlPBi9jZm9NVPeuBmntrtcO3NP/1HDsgLsTZsqKHD6KWIeJNRQnONcriWVaIcZYTKNykyCVUz93MAkGByqGSM49BAEDSAAwR" +
		"QIgZhTox7WpCb9krZMyHfgCzHwfu0FVqaJsO2Nl2ArhCX0CIQC5GgWD5jjCRlIWSEFSDo4DZgoQFXaQkJUSUbJZYpi9dA==\"]	}")
	var key jose.JSONWebKey
	err := json.Unmarshal(ec256TestBytes, &key)
	if err != nil {
		log.Fatal(err)
	}
	return &key
}

func Certificate(thingID string, thingKey crypto.PublicKey) *x509.Certificate {
	caWebKey := caSigningKey()
	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{CommonName: thingID},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(24 * time.Hour),
		},
		caWebKey.Certificates[0],
		thingKey,
		caWebKey.Key)
	if err != nil {
		log.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert)
	if err != nil {
		log.Fatal(err)
	}
	return certificate
}

func Signer(thingID string) crypto.Signer {
	var keySet jose.JSONWebKeySet
	err := json.Unmarshal([]byte(keyStore), &keySet)
	if err != nil {
		log.Fatal(err)
	}
	keys := keySet.Key(thingID)
	if len(keys) == 0 {
		log.Fatal("no key found for ", thingID)
	}
	return keys[0].Key.(*ecdsa.PrivateKey)
}
