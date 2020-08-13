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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"time"

	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"gopkg.in/square/go-jose.v2"
)

const (
	nextAvailablePort     = ":0"
	gatewayStartupMessage = "Thing Gateway server started"
)

func read(reader io.Reader, f func(string)) {
	go func() {
		in := bufio.NewReader(reader)
		for {
			s, err := in.ReadString('\n')
			if err != nil {
				return
			}
			f(s)
		}
	}()
}

func pipeToDebugger(reader io.Reader) {
	read(reader, func(s string) {
		anvil.DebugLogger.Print(s)
	})

}

func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func encodeKeyToPEM(signer crypto.Signer) ([]byte, error) {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), nil
}

func saveToTempFile(pattern string, content []byte) (*os.File, error) {
	file, err := ioutil.TempFile("", pattern)
	if err != nil {
		return nil, err
	}
	if _, err := file.Write(content); err != nil {
		return file, err
	}
	if err := file.Close(); err != nil {
		return file, err
	}
	return file, nil
}

// SimpleThingExample tests the simple thing example
type SimpleThingExample struct {
	anvil.NopSetupCleanup
}

func (t *SimpleThingExample) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *SimpleThingExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopRegCertTree)

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	ctx, cancel := testContext()
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "github.com/ForgeRock/iot-edge/v7/examples/thing/simple",
		"-url", state.URL().String(),
		"-realm", state.TestRealm(),
		"-audience", state.Audience(),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-key", string(key),
		"-keyid", data.Id.ThingKeys.Keys[0].KeyID)

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Run(); err != nil {
		anvil.DebugLogger.Println("cmd failed\n", err)
		return false
	}
	return true
}

// SimpleThingExampleTags tests the simple thing example with SDK build tags
type SimpleThingExampleTags struct {
	limitedTags bool
	anvil.NopSetupCleanup
}

func (t *SimpleThingExampleTags) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeDevice
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *SimpleThingExampleTags) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopRegCertTree)

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	tags := "http coap"
	if t.limitedTags {
		switch state.ClientType() {
		case anvil.AMClientType:
			tags = "http"
		case anvil.GatewayClientType:
			tags = "coap"
		default:
			return false
		}
	}

	ctx, cancel := testContext()
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "-tags", tags,
		"github.com/ForgeRock/iot-edge/v7/examples/thing/simple",
		"-url", state.URL().String(),
		"-realm", state.TestRealm(),
		"-audience", state.Audience(),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-key", string(key),
		"-keyid", data.Id.ThingKeys.Keys[0].KeyID)

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Run(); err != nil {
		anvil.DebugLogger.Println("cmd failed\n", err)
		return false
	}
	return true
}

func (t *SimpleThingExampleTags) NameSuffix() string {
	if t.limitedTags {
		return "Limited"
	}
	return "All"
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

	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}

	certificate, err := anvil.CreateCertificate(serverWebKey, data.Id.Name, data.Signer.Signer)
	if err != nil {
		return data, false
	}
	data.Certificates = []*x509.Certificate{certificate}
	data.Id.ThingType = callback.TypeDevice
	return data, true
}

func (t *CertRegistrationExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	state.SetGatewayTree(jwtPopRegCertTree)

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	// encode the certificate to PEM
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data.Certificates[0].Raw})

	ctx, cancel := testContext()
	defer cancel()

	cmd := exec.CommandContext(ctx, "go", "run", "github.com/ForgeRock/iot-edge/v7/examples/thing/cert-registration",
		"-url", state.URL().String(),
		"-realm", state.TestRealm(),
		"-audience", state.Audience(),
		"-tree", jwtPopRegCertTree,
		"-name", data.Id.Name,
		"-key", string(key),
		"-cert", string(cert))

	// send standard out and error to debugger
	stdout, _ := cmd.StdoutPipe()
	pipeToDebugger(stdout)
	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	if err := cmd.Run(); err != nil {
		anvil.DebugLogger.Println("cmd failed\n", err)
		return false
	}
	return true
}

// GatewayAppAuth tests the Gateway application with authentication only
type GatewayAppAuth struct {
	anvil.NopSetupCleanup
}

func (t *GatewayAppAuth) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeGateway
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *GatewayAppAuth) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// as this example involves a Thing Gateway there is no benefit of running it again during the gateway test set
		return true
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	keyFile, err := saveToTempFile("key*.pem", key)
	defer func() {
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
	}()
	if err != nil {
		anvil.DebugLogger.Printf("unable to save key to file; %v", err)
		return false
	}

	ctx, cancel := testContext()
	defer cancel()
	result := new(bool)

	cmd := exec.CommandContext(ctx, "go", "run", "github.com/ForgeRock/iot-edge/v7/cmd/gateway",
		"-d",
		"--timeout", "4s",
		"--url", state.URL().String(),
		"--realm", state.TestRealm(),
		"--audience", state.Audience(),
		"--tree", jwtPopAuthTree,
		"--name", data.Id.Name,
		"--address", nextAvailablePort,
		"--key", keyFile.Name())

	// watch stdout to see if the gateway as started up successfully
	stdout, _ := cmd.StdoutPipe()
	read(stdout, func(s string) {
		anvil.DebugLogger.Print(s)
		if match, _ := regexp.MatchString(gatewayStartupMessage, s); match {
			*result = true
			cancel()
		}
	})

	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	_ = cmd.Run()
	return *result
}

// GatewayAppAuthNonDefaultKID tests the Gateway application with authentication using a non-default key ID
type GatewayAppAuthNonDefaultKID struct {
	anvil.NopSetupCleanup
}

func (t *GatewayAppAuthNonDefaultKID) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}
	data.Id.ThingType = callback.TypeGateway
	// change KID
	data.Signer.KID = "keyOne"
	data.Id.ThingKeys.Keys[0].KeyID = data.Signer.KID
	return anvil.CreateIdentity(state.RealmForConfiguration(), data)
}

func (t *GatewayAppAuthNonDefaultKID) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// as this example involves a Thing Gateway there is no benefit of running it again during the gateway test set
		return true
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	keyFile, err := saveToTempFile("key*.pem", key)
	defer func() {
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
	}()
	if err != nil {
		anvil.DebugLogger.Printf("unable to save key to file; %v", err)
		return false
	}

	ctx, cancel := testContext()
	defer cancel()
	result := new(bool)

	cmd := exec.CommandContext(ctx, "go", "run", "github.com/ForgeRock/iot-edge/v7/cmd/gateway",
		"--debug",
		"--url", state.URL().String(),
		"--realm", state.TestRealm(),
		"--audience", state.Audience(),
		"--tree", jwtPopAuthTree,
		"--name", data.Id.Name,
		"--address", nextAvailablePort,
		"--key", keyFile.Name(),
		"--kid", data.Signer.KID)

	// watch stdout to see if the gateway as started up successfully
	stdout, _ := cmd.StdoutPipe()
	read(stdout, func(s string) {
		anvil.DebugLogger.Print(s)
		if match, _ := regexp.MatchString(gatewayStartupMessage, s); match {
			*result = true
			cancel()
		}
	})

	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	_ = cmd.Run()
	return *result
}

// GatewayAppReg tests the Gateway application with dynamic registration
type GatewayAppReg struct {
	anvil.NopSetupCleanup
}

func (t *GatewayAppReg) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var err error
	data.Id.Name = anvil.RandomName()

	serverWebKey, err := anvil.CertVerificationKey()
	if err != nil {
		return data, false
	}

	data.Id.ThingKeys, data.Signer, err = anvil.ConfirmationKey(jose.ES256)
	if err != nil {
		anvil.DebugLogger.Println("failed to generate confirmation key", err)
		return data, false
	}

	certificate, err := anvil.CreateCertificate(serverWebKey, data.Id.Name, data.Signer.Signer)
	if err != nil {
		return data, false
	}
	data.Certificates = []*x509.Certificate{certificate}
	data.Id.ThingType = callback.TypeDevice
	return data, true
}

func (t *GatewayAppReg) Run(state anvil.TestState, data anvil.ThingData) bool {
	if state.ClientType() == anvil.GatewayClientType {
		// as this example involves a Thing Gateway there is no benefit of running it again during the gateway test set
		return true
	}

	// encode the key to PEM
	key, err := encodeKeyToPEM(data.Signer.Signer)
	if err != nil {
		anvil.DebugLogger.Printf("unable to marshal private key; %v", err)
		return false
	}

	keyFile, err := saveToTempFile("key*.pem", key)
	defer func() {
		if keyFile != nil {
			os.Remove(keyFile.Name())
		}
	}()
	if err != nil {
		anvil.DebugLogger.Printf("unable to save key to file; %v", err)
		return false
	}

	certFile, err := saveToTempFile("cert*.pem",
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: data.Certificates[0].Raw}))
	defer func() {
		if certFile != nil {
			os.Remove(certFile.Name())
		}
	}()
	if err != nil {
		anvil.DebugLogger.Printf("unable to save cert to file; %v", err)
		return false
	}

	ctx, cancel := testContext()
	defer cancel()
	result := new(bool)

	cmd := exec.CommandContext(ctx, "go", "run", "github.com/ForgeRock/iot-edge/v7/cmd/gateway",
		"--debug",
		"--url", state.URL().String(),
		"--realm", state.TestRealm(),
		"--audience", state.Audience(),
		"--tree", jwtPopRegCertTree,
		"--name", data.Id.Name,
		"--address", nextAvailablePort,
		"--key", keyFile.Name(),
		"--cert", certFile.Name())

	// watch stdout to see if the gateway as started up successfully
	stdout, _ := cmd.StdoutPipe()
	read(stdout, func(s string) {
		anvil.DebugLogger.Print(s)
		if match, _ := regexp.MatchString(gatewayStartupMessage, s); match {
			*result = true
			cancel()
		}
	})

	stderr, _ := cmd.StderrPipe()
	pipeToDebugger(stderr)

	_ = cmd.Run()
	return *result
}
