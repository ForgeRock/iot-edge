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
	"os"

	"github.com/ForgeRock/iot-edge/v7/pkg/callback"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

func registerDevice() (err error) {
	var (
		urlString   = flag.String("url", "https://am.localtest.me:8080/am", "URL of AM or Gateway")
		realm       = flag.String("realm", "/", "AM Realm")
		authTree    = flag.String("tree", "iot-journey", "Authentication journey")
		thingName   = flag.String("name", "dynamic-smart-device", "Thing name")
		secretStore = flag.String("secrets", "./example.secrets", "Path to pre-created secret store")
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
	certs, err := store.Certificates(*thingName)
	if err != nil {
		return err
	}

	keyID, err := thing.JWKThumbprint(signer)
	if err != nil {
		return err
	}

	b := builder.Session().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateWith(callback.AuthenticateHandler{
			Audience: *realm,
			ThingID:  *thingName,
			KeyID:    keyID,
			Key:      signer,
			Claims:   nil,
		},
		callback.RegisterHandler{
			Audience:     *realm,
			ThingID:      *thingName,
			ThingType:    callback.TypeDevice,
			KeyID:        keyID,
			Key:          signer,
			Certificates: certs,
			Claims:       nil,
		})

	session, err := b.Create()
	if err != nil {
		return err
	}

	fmt.Printf("SSO Token: %s\n", session.Token())
	return nil
}

func main() {
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := registerDevice(); err != nil {
		log.Fatal(err)
	}
}
