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
	"flag"
	"fmt"
	"log"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func softwareStatement(key crypto.Signer, clientJWK jose.JSONWebKey, keyID, iss string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("alg", "ES256")
	opts.WithHeader("kid", keyID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{clientJWK},
	}
	jwtBuilder := jwt.Signed(signer).Claims(struct {
		Issuer       string             `json:"iss"`
		SoftwareID   string             `json:"software_id"`
		RedirectURIs []string           `json:"redirect_uris"`
		GrantTypes   []string           `json:"grant_types"`
		JWKS         jose.JSONWebKeySet `json:"jwks"`
	}{
		Issuer:       iss,
		SoftwareID:   uuid.New().String(),
		RedirectURIs: []string{"https://client.example.com:8443/callback"},
		GrantTypes:   []string{"client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		JWKS:         keySet,
	})
	response, err := jwtBuilder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return response, err
}

func main() {
	var (
		iss   = flag.String("iss", "https://soft-pub.example.com", "The software publisher issuer.")
		keyID = flag.String("keyID", "dYhQA7Fj9A8y1HuniPijRZ296DQIs5LngnqCrDP940k=", "The Key ID of the thing being registered.")
	)
	flag.Parse()

	softPubStore := secrets.Store{Path: "secrets.jwks"}
	softPubKey, _ := softPubStore.Signer(*iss)
	softPubKid, _ := thing.JWKThumbprint(softPubKey)

	thingStore := secrets.Store{Path: "secrets.jwks"}
	thingKey, _ := thingStore.Signer(*keyID)
	thingJWK := jose.JSONWebKey{KeyID: *keyID, Key: thingKey.Public(), Algorithm: string(jose.ES256), Use: "sig"}
	ss, err := softwareStatement(softPubKey, thingJWK, softPubKid, *iss)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(ss)
}
