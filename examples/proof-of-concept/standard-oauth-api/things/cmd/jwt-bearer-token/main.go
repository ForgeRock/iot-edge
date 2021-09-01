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
	"crypto"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"time"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var amURL *url.URL
var thingID = "4Y1SL65848Z411439"
var alg = jose.ES256
var algString = string(alg)

func jwtBearerToken(key crypto.Signer, subject, audience, kid string) (string, error) {
	opts := &jose.SignerOptions{}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return "", err
	}
	jwtBuilder := jwt.Signed(sig).
		Claims(jwt.Claims{
			Issuer:   subject,
			Subject:  subject,
			Audience: []string{audience},
			Expiry:   jwt.NewNumericDate(time.Now().Add(600 * time.Minute)),
		})
	token, err := jwtBuilder.Token()
	if err != nil {
		return "", err
	}
	token.Headers = []jose.Header{{
		KeyID:        kid,
		Algorithm:    algString,
	}}
	return jwtBuilder.CompactSerialize()
}

func registerDevice() (signer crypto.Signer, keyID string) {
	store := secrets.Store{}
	signer, _ = store.Signer(thingID)
	certificate, _ := store.Certificates(thingID)
	keyID, _ = thing.JWKThumbprint(signer)

	_, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(thingID, "/", keyID, signer, nil).
		RegisterThing(certificate, nil).
		Create()
	if err != nil {
		log.Fatal(thingID, " registration failed...", "\nReason: ", err)
	}
	log.Println(thingID, " registration successful")
	return signer, keyID
}

func main() {
	var (
		fqdn = flag.String("fqdn", "", "The FQDN of the ForgeOps deployment")
	)
	flag.Parse()

	if *fqdn == "" {
		log.Fatal("FQDN must be provided")
	}
	amURLString := "https://"+*fqdn+"/am"
	amURL, _ = url.Parse(amURLString)

	signer, kid := registerDevice()
	var keySet jose.JSONWebKeySet
	keySet.Keys = append(keySet.Keys,
		jose.JSONWebKey{KeyID: kid, Key: signer.Public(), Algorithm: algString, Use: "sig"})
	b, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Verification key set:")
	log.Println(string(b))

	signedJWT, err := jwtBearerToken(signer, thingID, amURLString+"/oauth2/access_token", kid)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
