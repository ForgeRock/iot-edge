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

func decodeCertificates(certs string) ([]*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certs))
	if block == nil {
		return nil, fmt.Errorf("unable to decode certificate")
	}
	return x509.ParseCertificates(block.Bytes)
}

// certRegThing initialises a Thing with AM.
// A successful initialisation means that the Thing has successfully registered and authenticated with AM.
func certRegThing() (err error) {
	var (
		urlString   = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm       = flag.String("realm", "/", "AM Realm")
		audience    = flag.String("audience", "/", "JWT audience")
		authTree    = flag.String("tree", "iot-tree", "Authentication tree")
		thingName   = flag.String("name", "dynamic-thing", "Thing name")
		key         = flag.String("key", "", "The Thing's key in PEM format")
		cert        = flag.String("cert", "", "The Thing's certificate in PEM format")
		secretStore = flag.String("secrets", "", "Path to pre-created secret store")
	)
	flag.Parse()

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	var signer crypto.Signer
	var certs []*x509.Certificate
	if *key != "" && *cert != "" {
		signer, err = decodePrivateKey(*key)
		if err != nil {
			return err
		}
		certs, err = decodeCertificates(*cert)
		if err != nil {
			return err
		}
	} else {
		store := secrets.Store{Path: *secretStore}
		signer, err = store.Signer(*thingName)
		if err != nil {
			return err
		}
		certs, err = store.Certificates(*thingName)
		if err != nil {
			return err
		}
	}

	// use key thumbprint as key id
	keyID, err := thing.JWKThumbprint(signer)
	if err != nil {
		return err
	}

	builder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(*thingName, *audience, keyID, signer, nil).
		RegisterThing(certs, nil)

	fmt.Printf("Creating Thing %s... ", *thingName)
	device, err := builder.Create()
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	fmt.Printf("Requesting access token... ")
	tokenResponse, err := device.RequestAccessToken("publish")
	if err != nil {
		return err
	}
	fmt.Println("Done")
	token, err := tokenResponse.AccessToken()
	if err != nil {
		return err
	}
	fmt.Println("Access token:", token)
	expiresIn, err := tokenResponse.ExpiresIn()
	if err != nil {
		return err
	}
	fmt.Println("Expires in:", expiresIn)
	scopes, err := tokenResponse.Scope()
	if err != nil {
		return err
	}
	fmt.Println("Scope(s):", scopes)

	return nil
}

func main() {
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := certRegThing(); err != nil {
		log.Fatal(err)
	}
}
