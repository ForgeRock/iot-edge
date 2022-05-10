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
	"encoding/json"
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
	thingName   = flag.String("name", "dynamic-thing", "Thing name")
	secretStore = flag.String("secrets", "", "Path to pre-created secret store")
	debug       = flag.Bool("debug", false, "Enable debug output")
)

// userTokenThing initialises a Thing with AM and retrieves an access token using OAuth 2.0 device authorization grant.
// The Thing will register and authenticate with AM and then request a user code.
// Once the Thing is in procession of a user code, it will direct the user to authorise the token.
// If successful, the Thing will receive an access token with the user that authorised the request as the subject.
func userTokenThing() (err error) {
	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	store := secrets.Store{Path: *secretStore}
	signer, err := store.Signer(*thingName)
	if err != nil {
		return err
	}
	certs, err := store.Certificates(*thingName)
	if err != nil {
		return err
	}

	// use key thumbprint as key id
	keyID, err := thing.JWKThumbprint(signer)
	if err != nil {
		return err
	}

	deviceBuilder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(*thingName, *audience, keyID, signer, nil).
		RegisterThing(certs, nil)

	fmt.Printf("Creating Thing %s... ", *thingName)
	device, err := deviceBuilder.Create()
	if err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Printf("\nRequesting user code... ")
	userCode, err := device.RequestUserCode("publish", "subscribe")
	if err != nil {
		return err
	}
	fmt.Println("Done\n", "User code response:", jsonString(userCode, false))

	fmt.Printf("Requesting user access token... To authorise the request, go to \n\n\t%s\n\n",
		userCode.VerificationURIComplete)
	tokenResponse, err := device.RequestUserToken(userCode)
	if err != nil {
		return err
	}
	fmt.Println("Done\n", "Access token response:", jsonString(tokenResponse.Content, true))

	token, err := tokenResponse.AccessToken()
	if err != nil {
		return err
	}
	if introspect(token, device) != nil {
		return err
	}

	refreshToken, err := tokenResponse.RefreshToken()
	if err != nil {
		return fmt.Errorf("no refresh token found in access token response")
	}
	fmt.Printf("\nRefreshing access token with reduced scope... ")
	tokenResponse, err = device.RefreshAccessToken(refreshToken, "publish")
	if err != nil {
		return err
	}
	fmt.Println("Done\n", "Access token response:", jsonString(tokenResponse.Content, true))

	token, err = tokenResponse.AccessToken()
	if err != nil {
		return err
	}
	if introspect(token, device) != nil {
		return err
	}

	return nil
}

func introspect(token string, device thing.Thing) error {
	fmt.Printf("\nIntrospecting access token to get more information... ")
	introspection, err := device.IntrospectAccessToken(token)
	if err != nil {
		return err
	}
	active, err := introspection.Active()
	if err != nil {
		return err
	}
	if !active {
		return fmt.Errorf("introspection indicates that the token is inactive")
	}
	fmt.Println("Done\n", "Introspection response:", jsonString(introspection.Content, true))
	return nil
}

func jsonString(v interface{}, indented bool) string {
	var js []byte
	if indented {
		js, _ = json.MarshalIndent(v, " ", "    ")
	} else {
		js, _ = json.Marshal(v)
	}
	return string(js)
}

func main() {
	flag.Parse()
	// pipe debug to standard out
	if *debug {
		thing.DebugLogger().SetOutput(os.Stdout)
	}
	if err := userTokenThing(); err != nil {
		fmt.Printf("Fatal error: %s", err)
		os.Exit(1)
	}
}
