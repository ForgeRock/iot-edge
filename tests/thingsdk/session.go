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
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"github.com/ForgeRock/iot-edge/pkg/thing"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
)

// SessionValid checks that the Session method returns true for a valid session
type SessionValid struct {
	anvil.NopSetupCleanup
}

func (t *SessionValid) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SessionValid) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	thing, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	valid, err := thing.Session().Valid()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
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
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SessionInvalid) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	thing, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	session := thing.Session()
	err = am.LogoutSession(session.Token())
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	}

	// check that session has been invalidated
	valid, err := session.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	} else if valid {
		anvil.DebugLogger.Println("invalidated session is shown as valid")
		return false
	}

	return true
}

// SessionReauthenticate checks that the Reauthenticate method creates a valid session and that the thing session is
// updated
type SessionReauthenticate struct {
	anvil.NopSetupCleanup
}

func (t *SessionReauthenticate) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SessionReauthenticate) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	thing, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	session := thing.Session()
	firstToken := session.Token()
	err = am.LogoutSession(firstToken)
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	}

	session, err = session.Reauthenticate()
	if err != nil {
		anvil.DebugLogger.Println("session re-authenticate failed", err)
		return false
	}

	// check that re-authenticated session is valid
	valid, err := session.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	} else if !valid {
		anvil.DebugLogger.Println("session is invalid")
		return false
	}

	// check that the session on the thing has been updated
	if firstToken == thing.Session().Token() {
		anvil.DebugLogger.Println("thing hasn't updated the session")
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
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SessionLogout) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	thing, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	session := thing.Session()
	err = session.Logout()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	}

	// check that session has been invalidated
	valid, err := session.Valid()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed", err)
		return false
	} else if valid {
		anvil.DebugLogger.Println("invalidated session is shown as valid")
		return false
	}

	return true
}
