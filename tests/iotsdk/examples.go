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
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
	"io"
	"os/exec"
	"time"
)

func pipeToDebugger(reader io.Reader) {
	go func() {
		in := bufio.NewReader(reader)
		for {
			s, err := in.ReadString('\n')
			if err != nil {
				return
			}
			anvil.DebugLogger.Print(s)
		}
	}()
}

func encodeKeyToPEM(signer crypto.Signer) (string, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})), nil
}

// SimpleThingExample tests the simple thing example
type SimpleThingExample struct {
	anvil.NopSetupCleanup
}

func (t *SimpleThingExample) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = things.TypeDevice
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SimpleThingExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	var server string
	var iecAddress string
	switch c := state.InitClients(jwtPopAuthTree).(type) {
	case *things.AMClient:
		server = "am"
	case *things.IECClient:
		server = "iec"
		iecAddress = c.Address
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/thing/simple",
		"-url", am.AMURL,
		"-realm", state.Realm(),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-server", server,
		"-address", iecAddress,
		"-key", key,
		"-keyid", data.Id.ThingKeys.Keys[0].KeyID)

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Start(); err != nil {
		anvil.DebugLogger.Println("cmd failed to start\n", err)
		return false
	}

	timer := time.AfterFunc(5*time.Second, func() {
		anvil.DebugLogger.Println("Timeout fired")
		cmd.Process.Kill()
	})
	defer timer.Stop()

	if err := cmd.Wait(); err != nil {
		anvil.DebugLogger.Println("cmd failed during wait\n", err)
		return false
	}
	return true
}

// SimpleIECExample tests the simple IEC example
type SimpleIECExample struct {
	anvil.NopSetupCleanup
}

func (t *SimpleIECExample) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = things.TypeIEC
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SimpleIECExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	switch state.InitClients(jwtPopAuthTree).(type) {
	case *things.IECClient:
		// as this example involves an IEC there is no benefit of running it again during the IEC test set
		return true
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/iec/simple",
		"-url", am.AMURL,
		"-realm", state.Realm(),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-address", ":0",
		"-key", key,
		"-keyid", data.Id.ThingKeys.Keys[0].KeyID)

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Start(); err != nil {
		anvil.DebugLogger.Println("cmd failed to start\n", err)
		return false
	}

	timer := time.AfterFunc(5*time.Second, func() {
		anvil.DebugLogger.Println("Timeout fired")
		cmd.Process.Kill()
	})
	defer timer.Stop()

	if err := cmd.Wait(); err != nil {
		anvil.DebugLogger.Println("cmd failed during wait\n", err)
		return false
	}
	return true
}

// CertRegistrationExample tests the certificate registration thing example
type CertRegistrationExample struct {
	anvil.NopSetupCleanup
}

func (t *CertRegistrationExample) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()

	serverWebKey, err := anvil.CertVerificationKey()
	if err != nil {
		return data, false
	}

	data.Id.ThingKeys, data.Signer, err = anvil.GenerateConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
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

func (t *CertRegistrationExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	var server string
	var iecAddress string
	switch c := state.InitClients(jwtPopRegCertTree).(type) {
	case *things.AMClient:
		server = "am"
	case *things.IECClient:
		server = "iec"
		iecAddress = c.Address
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	// encode the certificate to PEM
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data.Certificates[0].Raw})

	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/thing/cert-registration",
		"-url", am.AMURL,
		"-realm", state.Realm(),
		"-tree", jwtPopRegCertTree,
		"-name", data.Id.Name,
		"-server", server,
		"-address", iecAddress,
		"-key", key,
		"-keyid", data.Id.ThingKeys.Keys[0].KeyID,
		"-cert", string(cert))

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Start(); err != nil {
		anvil.DebugLogger.Println("cmd failed to start\n", err)
		return false
	}

	timer := time.AfterFunc(5*time.Second, func() {
		anvil.DebugLogger.Println("Timeout fired")
		cmd.Process.Kill()
	})
	defer timer.Stop()

	if err := cmd.Wait(); err != nil {
		anvil.DebugLogger.Println("cmd failed during wait\n", err)
		return false
	}
	return true
}
