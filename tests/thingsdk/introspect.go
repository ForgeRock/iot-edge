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
	"github.com/ForgeRock/iot-edge/internal/clock"
	"github.com/ForgeRock/iot-edge/internal/introspect"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"github.com/ForgeRock/iot-edge/pkg/thing"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"gopkg.in/square/go-jose.v2"
	"time"
)

func getAccessToken(thing thing.Thing) (string, error) {
	response, err := thing.RequestAccessToken("publish", "subscribe")
	if err != nil {
		return "", err
	}
	return response.AccessToken()
}

// IntrospectAccessToken checks that a valid access token can be introspected
type IntrospectAccessToken struct {
	clientBased         bool
	alg                 jose.SignatureAlgorithm
	originalOAuthConfig []byte
}

func (t *IntrospectAccessToken) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	t.originalOAuthConfig, err = anvil.ModifyOAuth2Provider(state.Realm(), t.clientBased, t.alg)
	if err != nil {
		anvil.DebugLogger.Println("failed to modify signing algorithm", err)
		return data, false
	}
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *IntrospectAccessToken) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	accessToken, err := getAccessToken(device)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	introspection, err := device.IntrospectAccessToken(accessToken)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	if !introspect.IsActive(introspection) {
		anvil.DebugLogger.Println("expected active = true")
		return false
	}
	anvil.DebugLogger.Println(string(introspection))
	return true
}

func (t IntrospectAccessToken) Cleanup(state anvil.TestState, data anvil.ThingData) error {
	return anvil.RestoreOAuth2Service(state.Realm(), t.originalOAuthConfig)
}

func (t *IntrospectAccessToken) NameSuffix() string {
	if !t.clientBased {
		return "CTSBased"
	}
	return "ClientBased" + string(t.alg)
}

// IntrospectAccessTokenFailure checks that introspection fails gracefully for unsupported cases
// Currently unsupported:
// * CTS-based tokens
// * Symmetrically signed tokens
type IntrospectAccessTokenFailure struct {
	IntrospectAccessToken
}

func (t *IntrospectAccessTokenFailure) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	accessToken, err := getAccessToken(device)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	_, err = device.IntrospectAccessToken(accessToken)
	if err == nil {
		anvil.DebugLogger.Println("expected failure")
		return false
	}
	anvil.DebugLogger.Println(err)
	return true
}

// IntrospectAccessTokenExpired tests that local introspection returns inactive if the token has expired
type IntrospectAccessTokenExpired struct {
	IntrospectAccessToken
}

func (t *IntrospectAccessTokenExpired) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	device, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	accessToken, err := getAccessToken(device)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	clock.Clock = func() time.Time {
		return time.Now().Add(24 * time.Hour)
	}
	defer func() {
		clock.Clock = clock.DefaultClock()
	}()

	introspection, err := device.IntrospectAccessToken(accessToken)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	if introspect.IsActive(introspection) {
		anvil.DebugLogger.Println("expected active = false")
		return false
	}
	return true
}

// IntrospectAccessTokenPremature tests that local introspection returns inactive if the token has not reached its
// not before time yet
type IntrospectAccessTokenPremature struct {
	IntrospectAccessToken
}

func (t *IntrospectAccessTokenPremature) Run(state anvil.TestState, data anvil.ThingData) bool {
	builder := thingJWTAuth(state, data)
	thing, err := builder.Create()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	response, err := thing.RequestAccessToken("publish", "subscribe")
	if err != nil {
		anvil.DebugLogger.Println("access token request failed", err)
		return false
	}

	accessToken, err := response.AccessToken()
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}

	clock.Clock = func() time.Time {
		return time.Now().Add(-24 * time.Hour)
	}
	defer func() {
		clock.Clock = clock.DefaultClock()
	}()

	introspection, err := thing.IntrospectAccessToken(accessToken)
	if err != nil {
		anvil.DebugLogger.Println(err)
		return false
	}
	if introspect.IsActive(introspection) {
		anvil.DebugLogger.Println("expected active = false")
		return false
	}
	return true
}
