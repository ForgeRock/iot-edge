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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

const secretsFile = ".secrets"

type popJWT struct {
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	ThingType string `json:"thingType"`
	Iat       int64  `json:"iat"`
	Exp       int64  `json:"exp"`
	Nonce     string `json:"nonce"`
	CNF       struct {
		KID string           `json:"kid,omitempty"`
		JWK *jose.JSONWebKey `json:"jwk,omitempty"`
	} `json:"cnf"`
}

func authJWT(subject, audience, kid, challenge string) (string, error) {
	keySet, err := readKeys()
	if err != nil {
		return "", err
	}
	keys := keySet.Key(kid)
	if len(keys) == 0 {
		return "", fmt.Errorf("no signing key found for kid %s", kid)
	}
	signer, ok := keys[0].Key.(crypto.Signer)
	if !ok {
		return "", fmt.Errorf("key associated with %s is not a signer", kid)
	}
	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: cryptosigner.Opaque(signer)}, opts)
	if err != nil {
		return "", err
	}
	claims := popJWT{
		Sub:   subject,
		Aud:   audience,
		Iat:   time.Now().Unix(),
		Exp:   time.Now().Add(5 * time.Minute).Unix(),
		Nonce: challenge,
	}
	claims.CNF.KID = kid
	builder := jwt.Signed(sig).Claims(claims)
	response, err := builder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return response, nil
}

func readKeys() (keySet jose.JSONWebKeySet, err error) {
	keySetBytes, err := ioutil.ReadFile(secretsFile)
	switch {
	case err == nil:
		err = json.Unmarshal(keySetBytes, &keySet)
	case os.IsNotExist(err):
		// this is okay, when the key set is written to disk and store will be created
		err = nil
	}
	return keySet, err
}

func writeKeys(keySet jose.JSONWebKeySet) error {
	b, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		return err
	}
	return ioutil.WriteFile(secretsFile, b, 0644)
}

func generateKey() (*jose.JSONWebKey, error) {
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	kid, err := thing.JWKThumbprint(newKey)
	if err != nil {
		return nil, err
	}
	keySet, err := readKeys()
	if err != nil {
		return nil, err
	}
	keySet.Keys = append(keySet.Keys, jose.JSONWebKey{KeyID: kid, Key: newKey, Algorithm: string(jose.ES256), Use: "sig"})
	err = writeKeys(keySet)
	if err != nil {
		return nil, err
	}
	return &jose.JSONWebKey{KeyID: kid, Key: &newKey.PublicKey}, nil
}

func main() {
	var (
		createKey = flag.Bool("key", false, "Generate a private key and store it in a file called .secrets as a JSON Web Key.")
		createJWT = flag.Bool("jwt", false, "Create a Proof of Possession JWT with the given sub, aud and kid.")
		subject   = flag.String("sub", "", "Subject of the JWT, typically the thing ID.")
		audience  = flag.String("aud", "/", "JWT audience, typically the realm path.")
		keyID     = flag.String("kid", "", "The Thing's key ID.")
		challenge = flag.String("challenge", "", "The Proof of Possession challenge received from the authentication callback.")
	)
	flag.Parse()

	if *createKey {
		publicJWK, err := generateKey()
		if err != nil {
			fmt.Println("key generation failed", err)
		}
		jsonJWK, err := publicJWK.MarshalJSON()
		if err != nil {
			fmt.Println("failed to marshall key", err)
		}
		fmt.Printf("\n{\"keys\":[%s]}\n", string(jsonJWK))
	}

	if *createJWT {
		popJWT, err := authJWT(*subject, *audience, *keyID, *challenge)
		if err != nil {
			fmt.Println("failed to create JWT", err )
		}
		fmt.Println(popJWT)
	}
}
