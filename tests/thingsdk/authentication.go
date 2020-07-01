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
	"gopkg.in/square/go-jose.v2"
)

func thingJWTAuth(state anvil.TestState, data anvil.ThingData) thing.Builder {
	state.SetGatewayTree(jwtPopAuthTree)
	return thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		AuthenticateWith(jwtPopAuthTree).
		HandleCallbacksWith(
			callback.AuthenticateHandler{
				Realm:   state.Realm(),
				ThingID: data.Id.Name,
				KeyID:   data.Signer.KID,
				Key:     data.Signer.Signer,
			})
}

// AuthenticateThingJWT tests the authentication of a pre-registered device
type AuthenticateThingJWT struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateThingJWT) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateThingJWT) Run(state anvil.TestState, data anvil.ThingData) bool {
	_, err := thingJWTAuth(state, data).Create()
	if err != nil {
		return false
	}
	return true
}

// AuthenticateThingJWTNonDefaultKID tests the authentication of a pre-registered device with a non-default key id
type AuthenticateThingJWTNonDefaultKID struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateThingJWTNonDefaultKID) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	// use a non-default key id
	data.Id.ThingKeys.Keys[0].KeyID = "pop.cnf"
	data.Signer.KID = "pop.cnf"

	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateThingJWTNonDefaultKID) Run(state anvil.TestState, data anvil.ThingData) bool {
	_, err := thingJWTAuth(state, data).Create()
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
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateWithoutConfirmationKey) Run(state anvil.TestState, data anvil.ThingData) bool {
	// add a signer to the thing data. AM will not know this key
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return false
	}
	_, err = thingJWTAuth(state, data).Create()
	if err != thing.ErrUnauthorised {
		anvil.DebugLogger.Println(err)
		return false
	}
	return true
}

// AuthenticateWithCustomClaims tests the authentication of a pre-registered device with a custom claim that is checked
// by a scripted decision node
type AuthenticateWithCustomClaims struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithCustomClaims) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateWithCustomClaims) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopAuthTreeCustomClaims)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		AuthenticateWith(jwtPopAuthTreeCustomClaims).
		HandleCallbacksWith(
			callback.AuthenticateHandler{
				Realm:   state.Realm(),
				ThingID: data.Id.Name,
				KeyID:   data.Signer.KID,
				Key:     data.Signer.Signer,
				Claims: func() interface{} {
					return struct {
						LifeUniverseEverything string `json:"life_universe_everything"`
					}{"42"}
				}})

	_, err := builder.Create()
	if err != nil {
		return false
	}
	return true
}

// AuthenticateWithCustomClaims tests the authentication of a pre-registered device fails when the value of a checked
// custom claim is incorrect
type AuthenticateWithIncorrectCustomClaim struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithIncorrectCustomClaim) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *AuthenticateWithIncorrectCustomClaim) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopAuthTreeCustomClaims)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		AuthenticateWith(jwtPopAuthTreeCustomClaims).
		HandleCallbacksWith(
			callback.AuthenticateHandler{
				Realm:   state.Realm(),
				ThingID: data.Id.Name,
				KeyID:   data.Signer.KID,
				Key:     data.Signer.Signer,
				Claims: func() interface{} {
					return struct {
						LifeUniverseEverything string `json:"life_universe_everything"`
					}{"0"}
				}})
	_, err := builder.Create()
	if err != thing.ErrUnauthorised {
		anvil.DebugLogger.Println(err)
		return false
	}
	return true
}

// AuthenticateWithUserPwd authenticates a thing using a username and password
type AuthenticateWithUserPwd struct {
	anvil.NopSetupCleanup
}

func (a AuthenticateWithUserPwd) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (a AuthenticateWithUserPwd) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		AuthenticateWith(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	_, err := builder.Create()
	if err != nil {
		return false
	}
	return true
}

// AuthenticateWithIncorrectPwd checks that authentication fails when the thing provides the wrong password
type AuthenticateWithIncorrectPwd struct {
	anvil.NopSetupCleanup
}

func (a AuthenticateWithIncorrectPwd) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (a AuthenticateWithIncorrectPwd) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := thing.New().
		ConnectTo(state.URL()).
		InRealm(state.Realm()).
		AuthenticateWith(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: "wrong"})
	_, err := builder.Create()
	if err != thing.ErrUnauthorised {
		anvil.DebugLogger.Println(err)
		return false
	}
	return true
}
