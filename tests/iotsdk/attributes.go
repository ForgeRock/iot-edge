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

// AttributesWithNoFilter requests all the thing's allowed attributes, which is configured in the IoT Service as
// `thingConfig` and `thingType`
type AttributesWithNoFilter struct {
	anvil.NopSetupCleanup
}

func (t *AttributesWithNoFilter) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return doSetup(state)
}

func (t *AttributesWithNoFilter) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	thing, err := builder.Initialise()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	response, err := thing.RequestAttributes()
	if err != nil {
		anvil.DebugLogger.Println("attributes request failed: ", err)
		return false
	}
	id, err := response.ID()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	thingConfig, err := response.GetFirst("thingConfig")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	thingType, err := response.GetFirst("thingType")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	return id == data.Id.Name && thingConfig == data.Id.ThingConfig && thingType == string(data.Id.ThingType)
}

// AttributesWithFilter requests a filtered list of the thing's allowed attributes, which is configured in the
// IoTService as `thingConfig` and `thingType`
type AttributesWithFilter struct {
	anvil.NopSetupCleanup
}

func (t *AttributesWithFilter) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return doSetup(state)
}

func (t *AttributesWithFilter) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	thing, err := builder.Initialise()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	response, err := thing.RequestAttributes("thingConfig")
	if err != nil {
		anvil.DebugLogger.Println("attributes request failed: ", err)
		return false
	}
	id, err := response.ID()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	thingConfig, err := response.GetFirst("thingConfig")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	_, err = response.GetFirst("thingType")
	if err == nil {
		anvil.DebugLogger.Println("expected thingType to be filtered out")
		return false
	}
	return id == data.Id.Name && thingConfig == data.Id.ThingConfig
}

func doSetup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = things.TypeDevice
	data.Id.ThingConfig = "host=localhost;port=80"
	return anvil.CreateIdentity(state.Realm(), data)
}

// AttributesWithNonRestrictedToken requests all the thing's allowed attributes with a non-restricted token
type AttributesWithNonRestrictedToken struct {
	anvil.NopSetupCleanup
}

func (t *AttributesWithNonRestrictedToken) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return doSetup(state)
}

func (t *AttributesWithNonRestrictedToken) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := state.Builder(userPwdAuthTree)
	builder.AddHandler(things.NameHandler{Name: data.Id.Name}).AddHandler(things.PasswordHandler{Password: data.Id.Password})
	thing, err := builder.Initialise()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	response, err := thing.RequestAttributes()
	if err != nil {
		anvil.DebugLogger.Println("attributes request failed: ", err)
		return false
	}
	id, err := response.ID()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	thingConfig, err := response.GetFirst("thingConfig")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	thingType, err := response.GetFirst("thingType")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	return id == data.Id.Name && thingConfig == data.Id.ThingConfig && thingType == string(data.Id.ThingType)
}
