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
	"time"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/google/uuid"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func jwtBearerToken(key crypto.Signer, issuer, subject, audience, kid string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("kid", kid)
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	return jwt.Signed(sig).
		Claims(jwt.Claims{
			Issuer:   issuer,
			Subject:  subject,
			Audience: []string{audience},
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			ID: uuid.New().String(),
		}).CompactSerialize()
}

func main() {
	var (
		amurl   = flag.String("amurl", "", "The AM URL of the ForgeOps deployment")
		keyID = flag.String("keyID", "dYhQA7Fj9A8y1HuniPijRZ296DQIs5LngnqCrDP940k=", "The Key ID of the registered thing.")
		clientID = flag.String("clientID", "", "The ID of the dynamically registered OAuth 2 client.")
	)
	flag.Parse()

	if *amurl == "" {
		log.Fatal("AM URL must be provided")
	}
	if *clientID == "" {
		log.Fatal("clientID must be provided")
	}

	store := secrets.Store{Path: "secrets.jwks"}
	signer, _ := store.Signer(*keyID)
	signedJWT, err := jwtBearerToken(signer, *clientID, *clientID, *amurl+"/oauth2/access_token", *keyID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
