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
	"bufio"
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
	amURL    = flag.String("url", "http://am.localtest.me:8080/am", "AM URL")
	amRealm  = flag.String("realm", "example", "AM Realm")
	authTree = flag.String("tree", "iot-tree", "Authentication tree")
	iecName  = flag.String("name", "simple-iec", "IEC name")
	address  = flag.String("address", "127.0.0.1:5688", "CoAP Address of IEC")
	key      = flag.String("key", "", "The IEC's key in PEM format")
	keyID    = flag.String("keyid", "pop.cnf", "The IEC's key ID")
	keyFile  = flag.String("keyfile", "./examples/resources/eckey1.key.pem", "The file containing the IEC's key")
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

// simpleIEC initialises an IEC with AM.
//
// To pre-provision an identity in AM, create an identity with
//	name: simple-iec
//	password: password
// Modify the "simple-iec" entry in DS
//	thingType: IEC
//	thingKeys: <see examples/resources/eckey1.jwks>
func simpleIEC() error {
	amKey, err := loadKey()
	if err != nil {
		return err
	}
	controller := things.NewIEC(*amURL, *amRealm, *authTree, []things.Handler{
		things.AuthenticateHandler{ThingID: *iecName, ConfirmationKeyID: *keyID, ConfirmationKey: amKey},
	})

	err = controller.Initialise()
	if err != nil {
		return err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	err = controller.StartCOAPServer(*address, serverKey)
	if err != nil {
		return err
	}
	defer controller.ShutdownCOAPServer()

	fmt.Println("IEC server started. Press a key to exit.")
	bufio.NewScanner(os.Stdin).Scan()
	return nil
}

func main() {
	flag.Parse()

	// pipe debug to standard out
	things.DebugLogger.SetOutput(os.Stdout)

	if err := simpleIEC(); err != nil {
		log.Fatal(err)
	}
}
