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
	"io/ioutil"
	"log"
	"net/url"
	"os"

	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

var (
	urlString = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
	realm     = flag.String("realm", "", "AM Realm")
	audience  = flag.String("audience", "/example", "JWT audience")
	authTree  = flag.String("tree", "iot-tree", "Authentication tree")
	thingName = flag.String("name", "dynamic-thing", "Thing name")
	key       = flag.String("key", "", "The Thing's key in PEM format")
	keyFile   = flag.String("keyfile", "./examples/resources/eckey1.key.pem", "The file containing the Thing's key")
	cert      = flag.String("cert", "", "The Thing's certificate in PEM format")
	certFile  = flag.String("certfile", "./examples/resources/dynamic-thing.cert.pem",
		"The file containing the Thing's certificate if it hasn't been handed directly to the function")
)

func loadKey() (crypto.Signer, error) {
	var err error
	var keyBytes []byte
	if *key != "" {
		keyBytes = []byte(*key)
	} else {
		keyBytes, err = ioutil.ReadFile(*keyFile)
		if err != nil {
			return nil, err
		}
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to decode key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey.(crypto.Signer), nil
}

func loadCertificates() ([]*x509.Certificate, error) {
	var err error
	var certBytes []byte
	if *cert != "" {
		certBytes = []byte(*cert)
	} else {
		certBytes, err = ioutil.ReadFile(*certFile)
		if err != nil {
			return nil, err
		}
	}
	block, _ := pem.Decode(certBytes)
	return x509.ParseCertificates(block.Bytes)
}

// userTokenThing initialises a Thing with AM and retrieves an access token using OAuth 2.0 device authorization grant.
// The Thing will register and authenticate with AM and then request a user code.
// Once the Thing is in procession of a user code, it will direct the user to authorise the token.
// If successful, the Thing will receive an access token with the user that authorised the request as the subject.
//
// To create your own certificate, refer to the cert-registration example.
func userTokenThing() (err error) {

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	key, err := loadKey()
	if err != nil {
		return err
	}

	// use key thumbprint as key id
	keyID, err := thing.JWKThumbprint(key)
	if err != nil {
		return err
	}

	certs, err := loadCertificates()
	if err != nil {
		return err
	}

	builder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(*thingName, *audience, keyID, key, nil).
		RegisterThing(certs, nil)

	fmt.Printf("Creating Thing %s... ", *thingName)
	device, err := builder.Create()
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	fmt.Printf("Requesting user code...")
	userCode, err := device.RequestUserCode("publish")
	if err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Printf("Requesting user access token... To authorise the request, go to \n\n\t%s?user_code=%s\n\n",
		userCode.VerificationURI, userCode.UserCode)
	thing.DebugLogger().SetOutput(ioutil.Discard) // switch off debug since user code requests are quite noisy
	tokenResponse, err := device.RequestUserToken(userCode)
	if err != nil {
		return err
	}
	fmt.Println("Done")
	thing.DebugLogger().SetOutput(os.Stdout)

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

	fmt.Printf("Introspecting access token to get more information...")
	introspection, err := device.IntrospectAccessToken(token)
	if err != nil {
		return err
	} else if !introspection.Active() {
		return fmt.Errorf("introspection indicates that the token is inactive")
	}
	fmt.Println("Done")
	scopes, err := introspection.Content.GetStringArray("scope")
	if err != nil {
		return err
	}
	sub, err := introspection.Content.GetString("sub")
	if err != nil {
		return err
	}
	fmt.Printf("User %s has authorised the following scope(s): %s", sub, scopes)

	return nil
}

func main() {
	flag.Parse()

	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := userTokenThing(); err != nil {
		log.Fatal(err)
	}
}
