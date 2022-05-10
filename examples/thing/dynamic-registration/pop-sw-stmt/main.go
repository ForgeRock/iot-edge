/*
 * Copyright 2022 ForgeRock AS
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
	"github.com/ForgeRock/iot-edge/examples/thing/dynamic-registration/jwtutil"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"gopkg.in/square/go-jose.v2"
)

var (
	urlString   = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
	realm       = flag.String("realm", "/", "AM Realm")
	audience    = flag.String("audience", "/", "JWT audience")
	authTree    = flag.String("tree", "iot-tree", "Authentication tree")
	thingName   = flag.String("name", "dynamic-pop-sw-stmt-thing", "Thing name")
	iss         = flag.String("iss", "https://soft-pub.example.com", "The software publisher issuer.")
	secretStore = flag.String("secrets", "", "Path to pre-created JWK set file")
	debug       = flag.Bool("debug", false, "Enable debug output")
)

// popWithSoftwareStatementRegistration registers and authenticates a Thing with AM, using the Proof of Possession
// with Software Statement registration method and the Proof of Possession authentication method.
func popWithSoftwareStatementRegistration() (err error) {
	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	thingStore := secrets.Store{Path: *secretStore}
	thingKey, _ := thingStore.Signer(*thingName)
	thingKid, _ := thing.JWKThumbprint(thingKey)
	thingJWK := jose.JSONWebKey{
		KeyID:     thingKid,
		Key:       thingKey.Public(),
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	ss, err := jwtutil.SoftwareStatement(*iss, thingJWK, nil)
	if err != nil {
		return err
	}

	deviceBuilder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		HandleCallbacksWith(
			callback.SoftwareStatementHandler(ss),
			callback.ProofOfPossessionHandler(*thingName, *audience, thingKid, thingKey))

	fmt.Printf("Creating Thing %s... ", *thingName)
	device, err := deviceBuilder.Create()
	if err != nil {
		return err
	}
	fmt.Println("Done")

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
	flag.Parse()
	// pipe debug to standard out
	if *debug {
		thing.DebugLogger().SetOutput(os.Stdout)
	}

	if err := popWithSoftwareStatementRegistration(); err != nil {
		fmt.Printf("Fatal error: %s", err)
		os.Exit(1)
	}
}
