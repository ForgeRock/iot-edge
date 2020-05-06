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
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"reflect"
	"sort"
	"strings"
)

// AccessTokenWithExactScopes requests an access token for a thing with specified scopes. The scopes matches the
// scopes configured in AM exactly.
type AccessTokenWithExactScopes struct {
	anvil.NopSetupCleanup
}

func (t *AccessTokenWithExactScopes) Setup(testCtx anvil.TestContext) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(testCtx.Realm(), data)
}

func (t *AccessTokenWithExactScopes) Run(testCtx anvil.TestContext, data anvil.ThingData) bool {
	thing := userPwdThing(testCtx, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	response, err := thing.RequestAccessToken("publish", "subscribe")
	if err != nil {
		anvil.DebugLogger.Println("access token request failed", err)
		return false
	}
	return verifyAccessTokenResponse(response, data.Id.Name, "publish", "subscribe")
}

// AccessTokenWithASubsetOfScopes requests an access token for a thing with specified scopes. The scopes are a
// subset of the scopes configured in AM.
type AccessTokenWithASubsetOfScopes struct {
	anvil.NopSetupCleanup
}

func (t *AccessTokenWithASubsetOfScopes) Setup(testCtx anvil.TestContext) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(testCtx.Realm(), data)
}

func (t *AccessTokenWithASubsetOfScopes) Run(testCtx anvil.TestContext, data anvil.ThingData) bool {
	thing := userPwdThing(testCtx, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	response, err := thing.RequestAccessToken("publish")
	if err != nil {
		anvil.DebugLogger.Println("access token request failed", err)
		return false
	}
	return verifyAccessTokenResponse(response, data.Id.Name, "publish")
}

// AccessTokenWithUnsupportedScopes requests an access token for a thing with specified scopes. The scopes do not
// match the scopes configured in AM so this request is expected to fail.
type AccessTokenWithUnsupportedScopes struct {
	anvil.NopSetupCleanup
}

func (t *AccessTokenWithUnsupportedScopes) Setup(testCtx anvil.TestContext) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(testCtx.Realm(), data)
}

func (t *AccessTokenWithUnsupportedScopes) Run(testCtx anvil.TestContext, data anvil.ThingData) bool {
	thing := userPwdThing(testCtx, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	_, err = thing.RequestAccessToken("publish", "subscribe", "delete")
	if err != nil && strings.Contains(err.Error(), "Unknown/invalid scope(s)") {
		return true
	}
	anvil.DebugLogger.Printf("expected request to fail with invalid scopes")
	return false
}

// AccessTokenWithNoScopes requests an access token for a thing with no scopes. The default scopes configured
// in AM is expected to be returned.
type AccessTokenWithNoScopes struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *AccessTokenWithNoScopes) Setup(testCtx anvil.TestContext) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(t.alg)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(testCtx.Realm(), data)
}

func (t *AccessTokenWithNoScopes) Run(testCtx anvil.TestContext, data anvil.ThingData) bool {
	thing := userPwdThing(testCtx, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	response, err := thing.RequestAccessToken()
	if err != nil {
		anvil.DebugLogger.Println("access token request failed", err)
		return false
	}
	return verifyAccessTokenResponse(response, data.Id.Name, "subscribe")
}

func (t *AccessTokenWithNoScopes) NameSuffix() string {
	return string(t.alg)
}

// AccessTokenFromCustomClient requests an access token for a thing. The OAuth 2.0 client used during the request
// is specified in the thing identity and contains a different set of scopes to those configured in the default IoT
// service OAuth 2.0 client.
type AccessTokenFromCustomClient struct {
	anvil.NopSetupCleanup
}

func (t *AccessTokenFromCustomClient) Setup(testCtx anvil.TestContext) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = "Device"
	data.Id.ThingOAuth2ClientName = "thing-oauth2-client"
	return anvil.CreateIdentity(testCtx.Realm(), data)
}

func (t *AccessTokenFromCustomClient) Run(testCtx anvil.TestContext, data anvil.ThingData) bool {
	thing := userPwdThing(testCtx, data)
	err := thing.Initialise()
	if err != nil {
		return false
	}
	response, err := thing.RequestAccessToken("create", "modify", "delete")
	if err != nil {
		anvil.DebugLogger.Println("access token request failed", err)
		return false
	}
	return verifyAccessTokenResponse(response, data.Id.Name, "create", "modify", "delete")
}

func verifyAccessTokenResponse(response payload.AccessTokenResponse, subject string, requestedScopes ...string) bool {
	token, err := response.AccessToken()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	accessJWT, err := jwt.ParseSigned(token)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	claims := &jwt.Claims{}
	if err := accessJWT.UnsafeClaimsWithoutVerification(claims); err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	if claims.Subject != subject {
		anvil.DebugLogger.Printf("access token subject, %s, not equal to thing ID, %s\n", claims.Subject, subject)
		return false
	}
	scope, err := response.GetString("scope")
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	receivedScopes := strings.Split(scope, " ")
	sort.Strings(receivedScopes)
	sort.Strings(requestedScopes)
	if !reflect.DeepEqual(requestedScopes, receivedScopes) {
		anvil.DebugLogger.Printf("received scopes %s not equal to requested scopes %s\n", receivedScopes, requestedScopes)
		return false
	}
	return true
}
