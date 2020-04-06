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
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/crypto"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"log"
	"os"
)

var (
	amURL     = flag.String("url", "http://openam.iectest.com:8080/openam", "AM URL")
	realm     = flag.String("realm", "example", "AM Realm")
	authTree  = flag.String("tree", "iot-user-pwd", "Authentication tree")
	thingName = flag.String("name", "simple-thing", "Thing name")
	thingPwd  = flag.String("pwd", "password", "Thing password")
)

// simpleThing initialises a Thing with AM.
// A successful initialisation means that the Thing has successfully authenticated with AM.
//
// Example setup:
// Start up the AM test container
// Create a realm called "example"
// Create the IoT username-password tree in the "example" realm and call it "iot-user-pwd"
// Create an identity with
//	name: simple-thing
//	password: password
// Modify the "simple-thing" entry in DS
//	thingType: Device
//	thingKeys: <see examples/resources/eckey1.jwks>
func simpleThing() error {
	fmt.Printf("Initialising client... ")

	// choose which client to use:
	// * AMCLient communicates directly with AM
	// * COAPClient communicates with AM via the IEC. Run the example IEC by calling "./run.sh examples simple/iec"

	client := things.NewAMClient(*amURL, *realm)
	err := client.Initialise()
	//client, err := things.NewCOAPClient("127.0.0.1:5688").Initialise()
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	key, err := crypto.LoadECPrivateKey("./examples/resources/eckey1.key.pem")
	if err != nil {
		return err
	}

	fmt.Printf("Initialising %s... ", *thingName)
	thing := things.Thing{
		Signer:   key,
		AuthTree: *authTree,
		Handlers: []message.CallbackHandler{
			message.NameCallbackHandler{Name: *thingName},
			message.PasswordCallbackHandler{Password: *thingPwd},
		},
	}
	err = thing.Initialise(client)
	if err != nil {
		return err
	}
	fmt.Printf("Done\n")

	return nil
}

func main() {
	flag.Parse()

	// pipe debug to standard out
	things.DebugLogger.SetOutput(os.Stdout)

	if err := simpleThing(); err != nil {
		log.Fatal(err)
	}
}
