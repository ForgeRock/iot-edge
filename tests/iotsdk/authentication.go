/*
 * Copyright 2020-2023 ForgeRock AS
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
	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"github.com/go-jose/go-jose/v3"
)

func thingJWTAuth(state anvil.TestState, data anvil.ThingData) thing.Builder {
	return thingJWTAuthWithAudience(state, data, state.RealmPath())
}

func thingJWTAuthWithAudience(state anvil.TestState, data anvil.ThingData, audience string) thing.Builder {
	state.SetGatewayTree(jwtAuthWithPoPTree)
	return builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, audience, data.Signer.KID, data.Signer.Signer, nil)
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
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateThingJWT) Run(state anvil.TestState, data anvil.ThingData) bool {
	success := true
	_, err := thingJWTAuthWithAudience(state, data, state.RealmPath()).Create()
	if err != nil {
		anvil.DebugLogger.Printf("failed to authenticate thing using PoP JWT with aud: %s; Error: %s\n",
			state.RealmPath(), err.Error())
		success = false
	}
	_, err = thingJWTAuthWithAudience(state, data, "custom-pop-audience").Create()
	if err != nil {
		anvil.DebugLogger.Printf("failed to authenticate thing using PoP JWT with aud: custom-pop-audience; Error: %s\n",
			err.Error())
		success = false
	}
	return success
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
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateThingJWTNonDefaultKID) Run(state anvil.TestState, data anvil.ThingData) bool {
	_, err := thingJWTAuth(state, data).Create()
	return err == nil
}

// AuthenticateWithoutConfirmationKey tests the authentication of a pre-registered device that has no confirmation key
// configured, which is expected to fail.
type AuthenticateWithoutConfirmationKey struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithoutConfirmationKey) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
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
	if !client.CodeUnauthorized.IsWrappedIn(err) {
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
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateWithCustomClaims) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtAuthWithPoPAndCustomClaimsTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithPoPAndCustomClaimsTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, func() interface{} {
			return struct {
				LifeUniverseEverything string `json:"life_universe_everything"`
			}{"42"}
		})

	_, err := builder.Create()
	return err == nil
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
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateWithIncorrectCustomClaim) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtAuthWithPoPAndCustomClaimsTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithPoPAndCustomClaimsTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, func() interface{} {
			return struct {
				LifeUniverseEverything string `json:"life_universe_everything"`
			}{"0"}
		})
	_, err := builder.Create()
	if !client.CodeUnauthorized.IsWrappedIn(err) {
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
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (a AuthenticateWithUserPwd) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: data.Id.Password})

	_, err := builder.Create()
	return err == nil
}

// AuthenticateWithIncorrectPwd checks that authentication fails when the thing provides the wrong password
type AuthenticateWithIncorrectPwd struct {
	anvil.NopSetupCleanup
}

func (a AuthenticateWithIncorrectPwd) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (a AuthenticateWithIncorrectPwd) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(userPwdAuthTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(userPwdAuthTree).
		HandleCallbacksWith(
			callback.NameHandler{Name: data.Id.Name},
			callback.PasswordHandler{Password: "wrong"})
	_, err := builder.Create()
	if !client.CodeUnauthorized.IsWrappedIn(err) {
		anvil.DebugLogger.Println(err)
		return false
	}
	return true
}

// AuthenticateThingThroughGateway tests authentication with the minimum setup required by the gateway
type AuthenticateThingThroughGateway struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateThingThroughGateway) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateThingThroughGateway) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtAuthWithPoPTree)
	_, err := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		Create()
	switch state.ClientType() {
	case anvil.GatewayClientType:
		if err != nil {
			return false
		}
	default:
		if err == nil {
			return false
		}
	}
	return true
}

func oauthAudienceValues(state anvil.TestState) []string {
	url := am.OAuthBaseURL(state.AMURL(), state.RealmPath(), state.DNSConfigured())
	return []string{url, url + "/access_token", "custom-client-assertion-audience"}
}

func thingJWTBearerAuth(state anvil.TestState, data anvil.ThingData, audience string) thing.Builder {
	state.SetGatewayTree(jwtAuthWithAssertionTree)
	return builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithAssertionTree).
		AuthenticateThing(data.Id.Name, audience, data.Signer.KID, data.Signer.Signer, nil)
}

// AuthenticateThingJWTBearer tests the authentication of a pre-registered device using a bearer JWT.
// The test will authenticate the thing once for each audience value.
type AuthenticateThingJWTBearer struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateThingJWTBearer) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err.Error())
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateThingJWTBearer) Run(state anvil.TestState, data anvil.ThingData) bool {
	success := true
	for _, audience := range oauthAudienceValues(state) {
		_, err := thingJWTBearerAuth(state, data, audience).Create()
		if err != nil {
			anvil.DebugLogger.Printf("failed to authenticate thing using bearer JWT with aud: %s", audience, err.Error())
			success = false
		}
	}
	return success
}

// AuthenticateWithCustomClaimsJWTBearer tests the authentication of a pre-registered device with a custom claim that
// is checked by a scripted decision node
type AuthenticateWithCustomClaimsJWTBearer struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateWithCustomClaimsJWTBearer) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateWithCustomClaimsJWTBearer) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtAuthWithAssertionAndCustomClaimsTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithAssertionAndCustomClaimsTree).
		AuthenticateThing(data.Id.Name, am.OAuthBaseURL(state.AMURL(), state.RealmPath(), state.DNSConfigured()),
			data.Signer.KID, data.Signer.Signer, func() interface{} {
				return struct {
					LifeUniverseEverything string `json:"life_universe_everything"`
				}{"42"}
			})

	_, err := thingBuilder.Create()
	return err == nil
}

// AuthenticateThingThroughGatewayWithJWTBearer tests authentication with the minimum setup required by the gateway
type AuthenticateThingThroughGatewayWithJWTBearer struct {
	anvil.NopSetupCleanup
}

func (t *AuthenticateThingThroughGatewayWithJWTBearer) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *AuthenticateThingThroughGatewayWithJWTBearer) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtAuthWithAssertionTree)
	_, err := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		AuthenticateThing(data.Id.Name, am.OAuthBaseURL(state.AMURL(), state.RealmPath(), state.DNSConfigured()),
			data.Signer.KID, data.Signer.Signer, nil).
		Create()
	switch state.ClientType() {
	case anvil.GatewayClientType:
		if err != nil {
			return false
		}
	default:
		if err == nil {
			return false
		}
	}
	return true
}
