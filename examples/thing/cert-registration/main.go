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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"io/ioutil"
	"log"
	"os"
)

var (
	amURL      = flag.String("url", "http://am.localtest.me:8080/am", "AM URL")
	amRealm    = flag.String("realm", "example", "AM Realm")
	authTree   = flag.String("tree", "iot-tree", "Authentication tree")
	thingName  = flag.String("name", "dynamic-thing", "Thing name")
	server     = flag.String("server", "am", "Server to connect to, am or iec")
	iecAddress = flag.String("address", "127.0.0.1:5688", "Address of IEC")
	key        = flag.String("key", "", "The Thing's key in PEM format")
	keyID      = flag.String("keyid", "pop.cnf", "The Thing's key ID")
	keyFile    = flag.String("keyfile", "./examples/resources/eckey1.key.pem", "The file containing the Thing's key")
	cert       = flag.String("cert", "", "The Thing's certificate in PEM format")
	certFile   = flag.String("certfile", "./examples/resources/dynamic-thing.cert.pem", "The file containing the Thing's certificate if it hasn't been handed directly to the function")
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

// certRegThing initialises a Thing with AM.
// A successful initialisation means that the Thing has successfully registered and authenticated with AM.
//
// To create your own certificate. Open a bash terminal:
// Choose an ID for your thing:
//     thingName=thingOne
// Use openssl to create a certificate signing request and a certificate:
//     openssl req -new -sha256 -subj "/CN=${thingName}" -key ./examples/resources/eckey1.key.pem -out "${thingName}.csr.pem"
//     openssl x509 -req -CA ./examples/resources/es256test.cert.pem -CAkey ./examples/resources/es256test.key.pem -CAcreateserial -in "${thingName}.csr.pem" -out "${thingName}.cert.pem"
// Ensure that the ID and the path to the certificate is passed to this example:
//     go run github.com/ForgeRock/iot-edge/examples/thing/cert-registration -name "${thingName}" -certfile "${thingName}.cert.pem"
func certRegThing() (err error) {

	// choose which client to use:
	// * AMClient communicates directly with AM
	// * IECClient communicates with AM via the IEC. Run the example IEC by calling "./run.sh examples simple/iec"

	var builder things.Builder
	if *server == "am" {
		builder = things.AMThing(*amURL, *amRealm, *authTree)
	} else if *server == "iec" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		builder = things.IECThing(*iecAddress, key)
	} else {
		log.Fatal("server not supported")
	}

	signer, err := loadKey()
	if err != nil {
		return err
	}

	certs, err := loadCertificates()
	if err != nil {
		return err
	}

	fmt.Printf("Creating Thing %s... ", *thingName)
	builder.AddHandler(things.AuthenticateHandler{ThingID: *thingName, ConfirmationKeyID: *keyID, ConfirmationKey: signer})
	builder.AddHandler(things.RegisterHandler{ThingID: *thingName, ThingType: things.TypeDevice, ConfirmationKeyID: *keyID,
		ConfirmationKey: signer, Certificates: certs})
	thing, err := builder.Initialise()
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	fmt.Printf("Requesting access token... ")
	tokenResponse, err := thing.RequestAccessToken("publish")
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
	scopes, err := tokenResponse.GetString("scope")
	if err != nil {
		return err
	}
	fmt.Println("Scope(s):", scopes)

	return nil
}

func main() {
	flag.Parse()

	// pipe debug to standard out
	things.DebugLogger.SetOutput(os.Stdout)

	if err := certRegThing(); err != nil {
		log.Fatal(err)
	}
}
