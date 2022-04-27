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
	"reflect"
	"sort"
	"strings"

	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
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
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	scope := []string{"publish", "subscribe"}
	if userToken, ok := requestUserToken(device, t.user, state.RealmForConfiguration(), scope...); ok {
		return introspectAndVerify(device, userToken, t.user.ID, scope...)
	}
	return false
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
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
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
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	_, err = device.RequestUserCode("publish", "subscribe", "delete")
	if err == nil {
		anvil.DebugLogger.Println("expected user code request to fail with invalid scopes")
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
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	if userToken, ok := requestUserToken(device, t.user, state.RealmForConfiguration()); ok {
		return introspectAndVerify(device, userToken, t.user.ID, "subscribe")
	}
	return false
}

func createDeviceAndUser(state anvil.TestState) (user am.IdAttributes, data anvil.ThingData, ok bool) {
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
	tokenScope, err := intro.Scope()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	tokenSub, err := intro.Content.GetString("sub")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	compoundSub := "(usr!" + subject + ")"
	if tokenSub != subject && tokenSub != compoundSub {
		anvil.DebugLogger.Printf("access token sub, %s, not equal to user ID, %s, or compound ID, %s\n",
			tokenSub, subject, compoundSub)
		return false
	}
	tokenSubname, _ := intro.Content.GetString("subname")
	if tokenSubname != "" && tokenSubname != subject {
		anvil.DebugLogger.Printf("access token subname, %s, not equal to user ID, %s\n", tokenSubname, subject)
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

// UserCodeExpiredSession requests a thing's User Code after the current session has been 'expired'
// We expect a new session to be created and for the request to succeed
type UserCodeExpiredSession struct {
	anvil.NopSetupCleanup
}

func (t *UserCodeExpiredSession) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *UserCodeExpiredSession) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	err = device.Logout()
	if err != nil {
		anvil.DebugLogger.Println("session logout failed: ", err)
		return false
	}
	_, err = device.RequestUserCode("publish", "subscribe")
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return false
	}
	return true
}

// UserTokenExpiredSession requests a thing's User Token after the current session has been 'expired'
// We expect a new session to be created and for the request to succeed
type UserTokenExpiredSession struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenExpiredSession) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	t.user, err = anvil.CreateUser(state.RealmForConfiguration())
	if err != nil {
		anvil.DebugLogger.Println("failed to create user", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *UserTokenExpiredSession) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	_, ok := requestUserToken(device, t.user, state.RealmForConfiguration(), "publish", "subscribe")
	return ok
}

// UserTokenRefresh requests an access token for a user and then uses the refresh token to refresh the access token.
// The new token should contain the same scope as the original token.
type UserTokenRefresh struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenRefresh) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenRefresh) Run(state anvil.TestState, data anvil.ThingData) bool {
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	scope := []string{"publish", "subscribe"}
	userToken, ok := requestUserToken(device, t.user, state.RealmForConfiguration(), scope...)
	if !ok {
		return false
	}
	if !introspectAndVerify(device, userToken, t.user.ID, scope...) {
		return false
	}
	refreshToken, err := userToken.RefreshToken()
	if err != nil {
		anvil.DebugLogger.Println("failed to read refresh token", err)
		return false
	}
	newUserToken, err := device.RefreshAccessToken(refreshToken)
	if err != nil {
		anvil.DebugLogger.Println("failed to refresh access token", err)
		return false
	}
	return introspectAndVerify(device, newUserToken, t.user.ID, scope...)
}

// UserTokenRefreshWithReducedScope requests an access token for a user and then uses the refresh token to refresh the
// access token with a reduced set of scopes. The new token must only contain the reduced set of scopes.
type UserTokenRefreshWithReducedScope struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenRefreshWithReducedScope) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenRefreshWithReducedScope) Run(state anvil.TestState, data anvil.ThingData) bool {
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	scope := []string{"publish", "subscribe"}
	userToken, ok := requestUserToken(device, t.user, state.RealmForConfiguration(), scope...)
	if !ok {
		return false
	}
	if !introspectAndVerify(device, userToken, t.user.ID, scope...) {
		return false
	}
	refreshToken, err := userToken.RefreshToken()
	if err != nil {
		anvil.DebugLogger.Println("failed to read refresh token", err)
		return false
	}
	reducedScope := []string{"publish"}
	newUserToken, err := device.RefreshAccessToken(refreshToken, reducedScope...)
	if err != nil {
		anvil.DebugLogger.Println("failed to refresh access token", err)
		return false
	}
	return introspectAndVerify(device, newUserToken, t.user.ID, reducedScope...)
}

// UserTokenRefreshWithIncreasedScope requests an access token for a user and then uses the refresh token to refresh the
// access token with an increased set of scopes. The request is expected to fail with an "invalid_scope" message.
type UserTokenRefreshWithIncreasedScope struct {
	anvil.NopSetupCleanup
	user am.IdAttributes
}

func (t *UserTokenRefreshWithIncreasedScope) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	t.user, data, ok = createDeviceAndUser(state)
	return
}

func (t *UserTokenRefreshWithIncreasedScope) Run(state anvil.TestState, data anvil.ThingData) bool {
	thingBuilder := thingJWTAuth(state, data)
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	scope := []string{"publish"}
	userToken, ok := requestUserToken(device, t.user, state.RealmForConfiguration(), scope...)
	if !ok {
		return false
	}
	if !introspectAndVerify(device, userToken, t.user.ID, scope...) {
		return false
	}
	refreshToken, err := userToken.RefreshToken()
	if err != nil {
		anvil.DebugLogger.Println("failed to read refresh token", err)
		return false
	}
	increasedScope := []string{"publish", "subscribe"}
	_, err = device.RefreshAccessToken(refreshToken, increasedScope...)
	if err != nil && strings.Contains(err.Error(), "invalid_scope") {
		return true
	}
	anvil.DebugLogger.Println("expected token refresh to fail")
	return false
}

func requestUserToken(device thing.Thing, user am.IdAttributes, realm string, scope...string) (
	userToken thing.AccessTokenResponse, success bool) {
	userCode, err := device.RequestUserCode(scope...)
	if err != nil {
		anvil.DebugLogger.Println("user code request failed: ", err)
		return userToken, false
	}
	err = am.SendUserConsent(realm, user, userCode, "allow")
	if err != nil {
		anvil.DebugLogger.Println("user consent request failed: ", err)
		return userToken, false
	}
	userToken, err = device.RequestUserToken(userCode)
	if err != nil {
		anvil.DebugLogger.Println("user token request failed: ", err)
		return userToken, false
	}
	return userToken, true
}