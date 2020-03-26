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
	"strings"

	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
)

func initialiseSDK(test anvil.BaseSDKTest) (*things.Thing, error) {
	var err error
	test.Client, err = anvil.TestAMClient().Initialise()
	if err != nil {
		return nil, err
	}
	thing := things.Thing{
		AuthTree: "Anvil-User-Pwd",
		Signer:   test.Signer,
		Handlers: []things.CallbackHandler{
			things.NameCallbackHandler{Name: test.Id.Name},
			things.PasswordCallbackHandler{Password: test.Id.Password},
		},
	}
	return &thing, thing.Initialise(test.Client)
}

// AuthenticateWithUsernameAndPassword tests the authentication of a pre-registered device
type AuthenticateWithUsernameAndPassword struct {
	anvil.BaseSDKTest
}

func (t *AuthenticateWithUsernameAndPassword) Setup() bool {
	var err error
	t.Id.ThingKeys, t.Signer, err = anvil.GenerateConfirmationKey()
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return false
	}
	t.Id.ThingType = "Device"
	return t.BaseSDKTest.Setup()
}

func (t *AuthenticateWithUsernameAndPassword) Run() bool {
	_, err := initialiseSDK(t.BaseSDKTest)
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
	_, err := initialiseSDK(t.BaseSDKTest)
	if err == nil {
		return false
	}
	return true
}

// SendTestCommand sends a test command request to AM
// TODO replace with specific command tests when thing.SendCommand has been removed
type SendTestCommand struct {
	anvil.BaseSDKTest
	thing *things.Thing
}

func (t *SendTestCommand) Setup() bool {
	var err error
	t.Id.ThingKeys, t.Signer, err = anvil.GenerateConfirmationKey()
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return false
	}
	t.Id.ThingType = "Device"
	if result := t.BaseSDKTest.Setup(); !result {
		return false
	}
	if t.thing, err = initialiseSDK(t.BaseSDKTest); err != nil {
		return false
	}
	return true
}

func (t *SendTestCommand) Run() bool {
	response, err := t.thing.SendCommand(t.Client)
	if err != nil {
		anvil.DebugLogger.Println("failed to send command", err)
		return false
	}
	if !strings.Contains(response, "TEST") {
		anvil.DebugLogger.Println("unexpected response: ", response)
		return false
	}
	return true
}
