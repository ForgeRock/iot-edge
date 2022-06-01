/*
 * Copyright 2020-2022 ForgeRock AS
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
	"net/url"
	"os"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

var (
	urlString   = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
	realm       = flag.String("realm", "/", "AM Realm")
	audience    = flag.String("audience", "/", "JWT audience")
	authTree    = flag.String("tree", "iot-tree", "Authentication tree")
	thingName   = flag.String("name", "manual-thing", "Thing name")
	secretStore = flag.String("secrets", "./resources/example.secrets", "Path to pre-created JWK set file")
	debug       = flag.Bool("debug", false, "Enable debug output")
)

// manualThing authenticates a Thing with AM, using manual registration and either Proof of Possession or
// Client Assertion authentication.
//
// To pre-provision an identity in AM, create an identity with
//	name: manual-thing
//	password: password
// Modify the "manual-thing" entry in DS
//	thingType: Device
//	thingKeys: <see examples/resources/manual-thing.jwks>
func manualThing() error {
	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	store := secrets.Store{Path: *secretStore}
	signer, err := store.Signer(*thingName)
	if err != nil {
		return err
	}
	keyID, _ := thing.JWKThumbprint(signer)

	builder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(*thingName, *audience, keyID, signer, nil)

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

	if err = device.Logout(); err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	// pipe debug to standard out
	if *debug {
		thing.DebugLogger().SetOutput(os.Stdout)
	}

	if err := manualThing(); err != nil {
		fmt.Printf("Fatal error: %s", err)
		os.Exit(1)
	}
}
