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

package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"log"
	"net/url"
	"os"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

func decodePrivateKey(key string) (crypto.Signer, error) {
	var err error
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, fmt.Errorf("unable to decode key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey.(crypto.Signer), nil
}

// simpleThing initialises a Thing with AM.
// A successful initialisation means that the Thing has successfully authenticated with AM.
//
// To pre-provision an identity in AM, create an identity with
//	name: simple-thing
//	password: password
// Modify the "simple-thing" entry in DS
//	thingType: Device
//	thingKeys: <see examples/resources/public.jwks>
func simpleThing() error {
	var (
		urlString   = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm       = flag.String("realm", "/", "AM Realm")
		audience    = flag.String("audience", "/", "JWT audience")
		authTree    = flag.String("tree", "iot-tree", "Authentication tree")
		thingName   = flag.String("name", "simple-thing", "Thing name")
		key         = flag.String("key", "", "The Thing's key in PEM format")
		keyID       = flag.String("keyid", "pop.cnf", "The Thing's key ID")
		secretStore = flag.String("secrets", "./example.secrets", "Path to pre-created JWK set file")
	)
	flag.Parse()

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	var signer crypto.Signer
	if *key != "" {
		signer, err = decodePrivateKey(*key)
		if err != nil {
			return err
		}
	} else {
		store := secrets.Store{Path: *secretStore}
		signer, err = store.Signer(*keyID)
		if err != nil {
			return err
		}
	}

	b := builder.Session().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateWith(callback.AuthenticateHandler{
		Audience: *audience,
		ThingID:  *thingName,
		KeyID:    *keyID,
		Key:      signer,
		Claims:   nil,
	})

	session, err := b.Create()
	if err != nil {
		return err
	}

	fmt.Printf("SSO Token: %s\n", session.Token())
	return nil
}

func main() {
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := simpleThing(); err != nil {
		log.Fatal(err)
	}
}
