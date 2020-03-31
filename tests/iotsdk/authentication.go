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
	"github.com/ForgeRock/iot-edge/pkg/message"
	"strings"

	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
)

func userPwdThing(data anvil.ThingData) *things.Thing {
	return &things.Thing{
		AuthTree: "Anvil-User-Pwd",
		Signer:   data.Signer,
		Handlers: []message.CallbackHandler{
			message.NameCallbackHandler{Name: data.Id.Name},
			message.PasswordCallbackHandler{Password: data.Id.Password},
		},
	}
}

// AuthenticateWithUsernameAndPassword tests the authentication of a pre-registered device
type AuthenticateWithUsernameAndPassword struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithUsernameAndPassword) Setup() (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey()
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(data)
}

func (t *AuthenticateWithUsernameAndPassword) Run(client things.Client, data anvil.ThingData) bool {
	thing := userPwdThing(data)
	err := thing.Initialise(client)
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

func (t *AuthenticateWithoutConfirmationKey) Setup() (data anvil.ThingData, ok bool) {
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(data)
}

func (t *AuthenticateWithoutConfirmationKey) Run(client things.Client, data anvil.ThingData) bool {
	thing := userPwdThing(data)
	err := thing.Initialise(client)
	if err == nil {
		return false
	}
	return true
}

// SendTestCommand sends a test command request to AM
// TODO replace with specific command tests when thing.SendCommand has been removed
type SendTestCommand struct {
	anvil.NopSetupCleanup
}

func (t *SendTestCommand) Setup() (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey()
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(data)
}

func (t *SendTestCommand) Run(client things.Client, data anvil.ThingData) bool {
	thing := userPwdThing(data)
	err := thing.Initialise(client)
	if err != nil {
		return false
	}
	response, err := thing.SendCommand(client)
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
