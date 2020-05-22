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
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"gopkg.in/square/go-jose.v2"
)

func jwtPoPAuthThing(state anvil.TestState, data anvil.ThingData) *things.Thing {
	kid := "pop.cnf"
	if len(data.Id.ThingKeys.Keys) > 0 {
		kid = data.Id.ThingKeys.Keys[0].KeyID
	}
	return things.NewThing(state.InitClients(jwtPopAuthTree), data.Signer, []things.Handler{
		things.JWTPoPAuthHandler{
			KID:       kid,
			Signer:    data.Signer,
			ThingId:   data.Id.Name,
			ThingType: data.Id.ThingType,
			Realm:     state.Realm(),
		},
	})
}

// AuthenticateWithJWTPoP tests the authentication of a pre-registered device
type AuthenticateWithJWTPoP struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithJWTPoP) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "device"
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateWithJWTPoP) Run(state anvil.TestState, data anvil.ThingData) bool {
	thing := jwtPoPAuthThing(state, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	return true
}

// AuthenticateWithoutConfirmationKey tests the authentication of a pre-registered device that has no confirmation key
// configured, which is expected to fail.
type AuthenticateWithoutConfirmationKey struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithoutConfirmationKey) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = "device"
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateWithoutConfirmationKey) Run(state anvil.TestState, data anvil.ThingData) bool {
	// add a signer to the thing data. AM will not know this key
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return false
	}
	thing := jwtPoPAuthThing(state, data)
	err = thing.Initialise()
	if err != things.ErrUnauthorised {
		anvil.DebugLogger.Println(err)
		return false
	}
	return true
}
