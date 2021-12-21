/*
 * Copyright 2021 ForgeRock AS
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
	"log"
	"net/url"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

func authorizeDevice() error {
	var (
		urlString   = flag.String("url", "https://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm       = flag.String("realm", "/", "AM Realm")
		authTree    = flag.String("tree", "iot-journey", "Authentication journey")
		thingName   = flag.String("name", "manual-smart-device", "Thing name")
		secretStore = flag.String("secrets", "./example.secrets", "Path to pre-created JWK set file")
		remoteKeyID = flag.String("keyid", "", "ID of the key store in the identity")
	)
	flag.Parse()

	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	store := secrets.Store{Path: *secretStore}
	signer, err := store.Signer(*thingName)
	if err != nil {
		return err
	}
	if *remoteKeyID == "" {
		keyID, err := thing.JWKThumbprint(signer)
		if err != nil {
			return err
		}
		remoteKeyID = &keyID
	}

	device, err := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(*thingName, *realm, *remoteKeyID, signer, nil).Create()
	if err != nil {
		return err
	}

	tokenResponse, err := device.RequestAccessToken()
	if err != nil {
		return err
	}
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
	//thing.DebugLogger().SetOutput(os.Stdout)

	if err := authorizeDevice(); err != nil {
		log.Fatal(err)
	}
}
