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
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
)

// SessionValid checks that the Session method returns true for a valid session
type SessionValid struct {
	anvil.NopSetupCleanup
}

func (t *SessionValid) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *SessionValid) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := builder.Session().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		AuthenticateWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	sesh, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	valid, err := sesh.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session validation failed", err)
		return false
	} else if !valid {
		anvil.DebugLogger.Println("session is invalid")
		return false
	}

	return true
}

// SessionInvalid checks that the Session method returns false for an invalidated session
type SessionInvalid struct {
	anvil.NopSetupCleanup
}

func (t *SessionInvalid) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *SessionInvalid) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := builder.Session().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		AuthenticateWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	sesh, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	err = am.LogoutSession(sesh.Token())
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	}

	// check that session has been invalidated
	valid, err := sesh.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session validation failed", err)
		return false
	} else if valid {
		anvil.DebugLogger.Println("invalidated session is shown as valid")
		return false
	}

	return true
}

// SessionLogout checks that the Logout method invalidates the session
type SessionLogout struct {
	anvil.NopSetupCleanup
}

func (t *SessionLogout) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *SessionLogout) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := builder.Session().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		AuthenticateWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	sesh, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	err = sesh.Logout()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	}

	// check that session has been invalidated
	valid, err := sesh.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session validation failed", err)
		return false
	} else if valid {
		anvil.DebugLogger.Println("invalidated session is shown as valid")
		return false
	}

	return true
}

// UnrestrictedSessionTokenAfterAuthentication tests if an unrestricted token obtained with JWT PoP authentication
// can be used to make a request to the things endpoint
type UnrestrictedSessionTokenAfterAuthentication struct {
	anvil.NopSetupCleanup
}

func (t *UnrestrictedSessionTokenAfterAuthentication) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *UnrestrictedSessionTokenAfterAuthentication) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopAuthUnrestrictedTokenTree)
	device, err := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtPopAuthUnrestrictedTokenTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to authenticate thing", err)
		return false
	}
	_, err = device.RequestAttributes()
	if err != nil {
		anvil.DebugLogger.Println("failed to retrieve thing attributes", err)
		return false
	}
	return true
}

// UnrestrictedSessionTokenAfterRegistration tests if an unrestricted token obtained with JWT PoP registration can be
// used to make a request to the things endpoint
type UnrestrictedSessionTokenAfterRegistration struct {
	anvil.NopSetupCleanup
}

func (t *UnrestrictedSessionTokenAfterRegistration) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistration(jose.ES256)
}

func (t *UnrestrictedSessionTokenAfterRegistration) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopRegCertUnrestrictedTokenTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtPopRegCertUnrestrictedTokenTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(data.Certificates, nil)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register thing", err)
		return false
	}
	_, err = device.RequestAttributes()
	if err != nil {
		anvil.DebugLogger.Println("failed to retrieve thing attributes", err)
		return false
	}
	return true
}