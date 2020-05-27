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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/crypto"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"log"
	"os"
)

var (
	amURL    = flag.String("url", "http://am.localtest.me:8080/am", "AM URL")
	amRealm  = flag.String("realm", "example", "AM Realm")
	authTree = flag.String("tree", "iot-tree", "Authentication tree")
	iecName  = flag.String("name", "simple-iec", "IEC name")
	address  = flag.String("address", "127.0.0.1:5688", "CoAP Address of IEC")
)

// simpleIEC initialises an IEC with AM.
//
// Example setup:
// Start up the AM test container
// Create a realm called "example"
// Create the IoT tree in the "example" realm and call it "iot-tree"
// Create an identity with
//	name: simple-iec
//	password: password
// Modify the "simple-iec" entry in DS
//	thingType: IEC
//	thingKeys: <see examples/resources/eckey1.jwks>
func simpleIEC() error {
	amKey, err := crypto.LoadECPrivateKey("./examples/resources/eckey1.key.pem")
	if err != nil {
		return err
	}
	controller := things.NewIEC(things.SigningKey{KID: "pop.cnf", Signer: amKey}, *amURL, *amRealm, *authTree, []things.Handler{
		things.ThingJWTHandler{ThingID: *iecName},
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
