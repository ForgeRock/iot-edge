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
	"context"

	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
)

func initialiseSDK(id am.IdAttributes) error {
	thing := things.Thing{
		Client: things.AMClient{AuthURL: anvil.TreeURL("Anvil-User-Pwd")},
		Handlers: []things.CallbackHandler{
			things.NameCallbackHandler{Name: id.Name},
			things.PasswordCallbackHandler{Password: id.Password},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), anvil.StdTimeOut)
	defer cancel()
	return thing.Initialise(ctx)
}

// AuthenticateWithUsernameAndPassword tests the authentication of a pre-registered device
type AuthenticateWithUsernameAndPassword struct {
	anvil.BaseSDKTest
}

func (t *AuthenticateWithUsernameAndPassword) Setup() bool {
	_, publicJWK, err := anvil.GenerateConfirmationKey()
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return false
	}
	t.Id.ThingType = "Device"
	t.Id.ThingKeys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{*publicJWK}}
	return t.BaseSDKTest.Setup()
}

func (t *AuthenticateWithUsernameAndPassword) Run() bool {
	err := initialiseSDK(t.Id)
	if err != nil {
		return false
	}
	return true
}

// AuthenticateWithoutConfirmationKey tests the authentication of a pre-registered device that has no confirmation key
// configured, which is expected to fail.
type AuthenticateWithoutConfirmationKey struct {
	anvil.BaseSDKTest
}

func (t *AuthenticateWithoutConfirmationKey) Setup() bool {
	t.Id.ThingType = "Device"
	return t.BaseSDKTest.Setup()
}

func (t *AuthenticateWithoutConfirmationKey) Run() bool {
	err := initialiseSDK(t.Id)
	if err == nil {
		return false
	}
	return true
}
