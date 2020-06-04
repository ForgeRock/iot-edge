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
	"crypto/x509"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"gopkg.in/square/go-jose.v2"
)

// RegisterThingCert tests the dynamic registration of a device with a valid x509 certificate
type RegisterThingCert struct {
	anvil.NopSetupCleanup
}

func (t *RegisterThingCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	serverWebKey, err := anvil.CertVerificationKey()
	if err != nil {
		return data, false
	}

	certificate, err := anvil.CreateCertificate(serverWebKey, data.Id.Name, data.Signer.Signer)
	if err != nil {
		return data, false
	}
	data.Certificates = []*x509.Certificate{certificate}
	data.Id.ThingType = things.TypeDevice
	return data, true
}

func (t *RegisterThingCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	thing := things.NewThing(state.InitClients(jwtPopRegCertTree), data.Signer, []things.Handler{
		things.AuthenticateHandler{ThingID: data.Id.Name},
		things.RegisterHandler{ThingID: data.Id.Name, Certificates: data.Certificates},
	})
	err := thing.Initialise()
	if err != nil {
		return false
	}
	return true
}

// RegisterThingCertWithoutCert tries to dynamically register a device without a x509 certificate
type RegisterThingWithoutCert struct {
	anvil.NopSetupCleanup
}

func (t *RegisterThingWithoutCert) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}

	data.Id.ThingType = things.TypeDevice
	return data, true
}

func (t *RegisterThingWithoutCert) Run(state anvil.TestState, data anvil.ThingData) bool {
	thing := things.NewThing(state.InitClients(jwtPopRegCertTree), data.Signer, []things.Handler{
		things.AuthenticateHandler{ThingID: data.Id.Name},
		things.RegisterHandler{ThingID: data.Id.Name, Certificates: data.Certificates},
	})
	err := thing.Initialise()
	if err != things.ErrUnauthorised {
		anvil.DebugLogger.Printf("Expected Not Authorised; got %v", err)
		return false
	}
	return true
}
