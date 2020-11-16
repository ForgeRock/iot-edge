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
	"reflect"
	"sort"
	"strings"

	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
)

// UserTokenAllow requests an access token for a user and the user consents to the token being issued.
// The scopes matches the scopes configured in AM exactly.
type UserTokenAllow struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenAllow) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenAllow) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// this can be removed when the gateway functionality has been added
		return true
	}
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	userCode, err := device.RequestUserCode("publish", "subscribe")
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return false
	}
	err = am.SendUserConsent(state.RealmForConfiguration(), t.user, userCode, "allow")
	if err != nil {
		anvil.DebugLogger.Println("user consent request failed: ", err)
		return false
	}
	userToken, err := device.RequestUserToken(userCode)
	if err != nil {
		anvil.DebugLogger.Println("user token request failed: ", err)
		return false
	}
	return introspectAndVerify(device, userToken, t.user.Name, "publish", "subscribe")
}

// UserTokenDeny requests an access token for a user, but the user does not consent to the token being issued.
type UserTokenDeny struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenDeny) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenDeny) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// this can be removed when the gateway functionality has been added
		return true
	}
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	userCode, err := device.RequestUserCode("publish", "subscribe")
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return false
	}
	err = am.SendUserConsent(state.RealmForConfiguration(), t.user, userCode, "deny")
	if err != nil {
		anvil.DebugLogger.Println("user consent request failed: ", err)
		return false
	}
	_, err = device.RequestUserToken(userCode)
	if err == nil {
		anvil.DebugLogger.Println("expected user token request to fail with authorization_declined")
		return false
	}
	anvil.DebugLogger.Println("user consent error: ", err)
	return strings.Contains(err.Error(), "authorization_declined")
}

// UserTokenWithUnsupportedScopes requests an access token for a user and the user consents to the token being issued.
// The scopes do not match the scopes configured in AM so this request is expected to fail.
type UserTokenWithUnsupportedScopes struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenWithUnsupportedScopes) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenWithUnsupportedScopes) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// this can be removed when the gateway functionality has been added
		return true
	}
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	userCode, err := device.RequestUserCode("publish", "subscribe", "delete")
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return false
	}
	err = am.SendUserConsent(state.RealmForConfiguration(), t.user, userCode, "allow")
	if err == nil {
		anvil.DebugLogger.Println("expected user consent request to fail with invalid scopes")
		return false
	}
	anvil.DebugLogger.Println("invalid scopes error: ", err)
	return strings.Contains(err.Error(), "Unknown/invalid scope(s)")
}

// UserTokenWithNoScopes requests an access token for a user and the user consents to the token being issued.
// No scopes are specified in the request so the default scopes configured in AM is expected to be returned.
type UserTokenWithNoScopes struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenWithNoScopes) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenWithNoScopes) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// this can be removed when the gateway functionality has been added
		return true
	}
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	userCode, err := device.RequestUserCode()
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return false
	}
	err = am.SendUserConsent(state.RealmForConfiguration(), t.user, userCode, "allow")
	if err != nil {
		anvil.DebugLogger.Println("user consent request failed: ", err)
		return false
	}
	userToken, err := device.RequestUserToken(userCode)
	if err != nil {
		anvil.DebugLogger.Println("user token request failed: ", err)
		return false
	}
	return introspectAndVerify(device, userToken, t.user.Name, "subscribe")
}

func createDeviceAndUser(state anvil.TestState) (user am.IdAttributes, data anvil.ThingData, ok bool) {
	if state.ClientType() == anvil.GatewayClientType {
		// this can be removed when the gateway functionality has been added
		return user, data, true
	}
	var err error
	user, err = anvil.CreateUser(state.RealmForConfiguration())
	if err != nil {
		anvil.DebugLogger.Println("failed to create user", err)
		return user, data, false
	}
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return user, data, false
	}
	data.Id.ThingType = callback.TypeDevice
	data, ok = anvil.CreateIdentity(state.RealmForConfiguration(), data)
	return
}

// introspectAndVerify will make an introspection call and verify the subject an scope of the token
func introspectAndVerify(device thing.Thing, tokenResponse thing.AccessTokenResponse, subject string,
	requestedScopes ...string) bool {

	token, err := tokenResponse.AccessToken()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	intro, err := device.IntrospectAccessToken(token)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	tokenScope, err := intro.Content.GetStringArray("scope")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	tokenSubject, err := intro.Content.GetString("sub")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	if tokenSubject != subject {
		anvil.DebugLogger.Printf("access token subject, %s, not equal to thing ID, %s\n", tokenSubject, subject)
		return false
	}
	sort.Strings(tokenScope)
	sort.Strings(requestedScopes)
	if !reflect.DeepEqual(requestedScopes, tokenScope) {
		anvil.DebugLogger.Printf("received scopes %s not equal to requested scopes %s\n", tokenScope, requestedScopes)
		return false
	}
	return true
}
