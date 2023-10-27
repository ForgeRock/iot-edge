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
	"crypto/x509"
	"encoding/json"
	"strings"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"github.com/go-jose/go-jose/v3"
)

func populateThingDataForRegistrationWithCert(alg jose.SignatureAlgorithm) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(alg)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	certificate, err := anvil.CreateCertificate(data.Id.Name, data.Signer.Signer)
	if err != nil {
		return data, false
	}
	data.Certificates = []*x509.Certificate{certificate}
	return data, true
}

func populateThingDataForRegistrationWithSoftState() (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.SoftwareStatement, err = anvil.CreateSoftwareStatement(data.Id.ThingKeys.Keys[0])
	if err != nil {
		anvil.DebugLogger.Println("failed to create software statement", err)
		return data, false
	}
	return data, true
}

// RegisterDeviceCert tests the dynamic registration of a device with a valid x509 certificate
type RegisterDeviceCert struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(t.alg)
}

func (t *RegisterDeviceCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(data.Certificates, nil)
	_, err := builder.Create()
	return err == nil
}

func (t *RegisterDeviceCert) NameSuffix() string {
	return string(t.alg)
}

// RegisterDeviceWithoutCert tries to dynamically register a device without a x509 certificate
type RegisterDeviceWithoutCert struct {
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceWithoutCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	return data, true
}

func (t *RegisterDeviceWithoutCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(nil, nil)

	_, err := builder.Create()
	if !client.CodeUnauthorized.IsWrappedIn(err) {
		anvil.DebugLogger.Printf("Expected Not Authorised; got %v", err)
		return false
	}
	return true
}

// RegisterDeviceWithAttributes tests the dynamic registration of a device with custom attributes
type RegisterDeviceWithAttributes struct {
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceWithAttributes) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(jose.ES256)
}

func (t *RegisterDeviceWithAttributes) Run(state anvil.TestState, data anvil.ThingData) bool {
	type Properties struct {
		IPAddress    string `json:"ipAddress"`
		MACAddress   string `json:"macAddress"`
		SerialNumber string `json:"serialNumber"`
	}
	deviceProps := Properties{
		IPAddress:    "123.12.34.56",
		MACAddress:   "00:25:96:FF:FE:12:34:56",
		SerialNumber: "091238653509134865",
	}
	props, _ := json.Marshal(deviceProps)
	sdkAttribute := struct {
		ThingProperties string `json:"thingProperties"`
	}{
		ThingProperties: string(props),
	}
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(data.Certificates, func() interface{} {
			return sdkAttribute
		})
	device, err := builder.Create()
	if err != nil {
		return false
	}
	deviceAttrs, err := device.RequestAttributes()
	if err != nil {
		return false
	}
	thingProps, err := deviceAttrs.GetFirst("thingProperties")
	if err != nil {
		anvil.DebugLogger.Printf("Getting thing properties failed; %s", deviceAttrs, err)
		return false
	}
	var readProps Properties
	err = json.Unmarshal([]byte(thingProps), &readProps)
	if err != nil {
		anvil.DebugLogger.Printf("Unmarshalling properties failed ; %s", thingProps, err)
		return false
	}
	if readProps.IPAddress != deviceProps.IPAddress ||
		readProps.MACAddress != deviceProps.MACAddress ||
		readProps.SerialNumber != deviceProps.SerialNumber {
		anvil.DebugLogger.Printf("Expected attribute value %v; got %s", sdkAttribute, thingProps)
		return false
	}
	return true
}

// RegisterServiceCert tests dynamic registration of a service with a valid x509 certificate
type RegisterServiceCert struct {
	anvil.NopSetupCleanup
}

func (t *RegisterServiceCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(jose.ES256)
}

func (t *RegisterServiceCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(data.Certificates, nil).
		AsService()

	service, err := builder.Create()
	if err != nil {
		return false
	}
	serviceAttrs, err := service.RequestAttributes()
	if err != nil {
		return false
	}
	thingType, err := serviceAttrs.GetFirst("thingType")
	if err != nil {
		anvil.DebugLogger.Printf("Getting thing type failed; %s", serviceAttrs, err)
		return false
	}
	if strings.ToLower(thingType) != "service" {
		anvil.DebugLogger.Printf("Expected thing type service; got %s", thingType)
		return false
	}
	return true
}

// RegisterDeviceNoKeyID checks that dynamic registration fails gracefully when no key is provided
type RegisterDeviceNoKeyID struct {
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceNoKeyID) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(jose.ES256)
}

func (t *RegisterDeviceNoKeyID) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), "", data.Signer.Signer, nil).
		RegisterThing(data.Certificates, nil)
	_, err := builder.Create()
	return err != nil
}

// RegisterDeviceNoKey checks that dynamic registration fails gracefully when no key is provided
type RegisterDeviceNoKey struct {
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceNoKey) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	data.Id.Name = anvil.RandomName()
	return data, true
}

func (t *RegisterDeviceNoKey) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree)
	builder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithPoPTree).
		AuthenticateThing(data.Id.Name, state.RealmPath(), "", nil, nil).
		RegisterThing(data.Certificates, nil)
	_, err := builder.Create()
	return err != nil
}

// RegisterDeviceCertJWTBearer tests the dynamic registration of a device with a valid x509 certificate that uses a
// bearer JWT for authentication and a custom audience value
type RegisterDeviceCertJWTBearer struct {
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceCertJWTBearer) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(jose.ES256)
}

func (t *RegisterDeviceCertJWTBearer) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertAndJWTAuthWithAssertionTree)
	_, err := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertAndJWTAuthWithAssertionTree).
		AuthenticateThing(data.Id.Name, "custom-client-assertion-audience", data.Signer.KID, data.Signer.Signer, nil).
		RegisterThing(data.Certificates, nil).
		Create()
	return err == nil
}

// RegisterDeviceSoftState tests the dynamic registration of a device with a software statement
type RegisterDeviceSoftState struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *RegisterDeviceSoftState) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithSoftState()
}

func (t *RegisterDeviceSoftState) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithSoftStateTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithSoftStateTree).
		HandleCallbacksWith(callback.SoftwareStatementHandler(data.SoftwareStatement))
	device, err := thingBuilder.Create()
	if err != nil {
		anvil.DebugLogger.Println("failed to register device", err)
		return false
	}
	attrs, err := device.RequestAttributes()
	if err != nil {
		anvil.DebugLogger.Println("failed to retrieve attributes", err)
		return false
	}
	thingID, err := attrs.ID()
	if err != nil {
		anvil.DebugLogger.Println(err.Error())
		return false
	}
	state.SetGatewayTree(jwtAuthWithAssertionTree)
	thingBuilder = builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtAuthWithAssertionTree).
		AuthenticateThing(thingID, am.OAuthBaseURL(state.AMURL(), state.RealmPath(), state.DNSConfigured()),
			data.Signer.KID, data.Signer.Signer, nil)
	_, err = thingBuilder.Create()
	return err == nil
}

// RegisterDevicePopAndSoftState tests the dynamic registration of a device with a PoP JWT and a software statement
type RegisterDevicePopAndSoftState struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *RegisterDevicePopAndSoftState) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithSoftState()
}

func (t *RegisterDevicePopAndSoftState) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithSoftStateTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithSoftStateTree).
		HandleCallbacksWith(
			callback.ProofOfPossessionHandler(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer),
			callback.SoftwareStatementHandler(data.SoftwareStatement))
	_, err := thingBuilder.Create()
	return err == nil
}

// RegisterDevicePop tests the dynamic registration of a device with a PoP JWT
type RegisterDevicePop struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *RegisterDevicePop) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	return data, true
}

func (t *RegisterDevicePop) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPTree).
		HandleCallbacksWith(
			callback.ProofOfPossessionHandler(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer))
	_, err := thingBuilder.Create()
	return err == nil
}

// RegisterDevicePopAndCert tests the dynamic registration of a device with a valid x509 certificate
// Use only registration and HandleCallbacksWith method
type RegisterDevicePopAndCert struct {
	alg jose.SignatureAlgorithm
	anvil.NopSetupCleanup
}

func (t *RegisterDevicePopAndCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	return populateThingDataForRegistrationWithCert(jose.ES256)
}

func (t *RegisterDevicePopAndCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtRegWithPoPWithCertTree)
	thingBuilder := builder.Thing().
		ConnectTo(state.ConnectionURL()).
		InRealm(state.Realm()).
		WithTree(jwtRegWithPoPWithCertTree).
		HandleCallbacksWith(
			callback.ProofOfPossessionHandler(data.Id.Name, state.RealmPath(), data.Signer.KID, data.Signer.Signer).
				WithCertificate(data.Certificates))
	_, err := thingBuilder.Create()
	return err == nil
}
