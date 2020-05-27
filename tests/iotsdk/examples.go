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
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
	"io"
	"os/exec"
	"time"
)

var thingJWK = "{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"alg\":\"ES256\"," +
	"\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\"}"

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

// SimpleThingExample tests the simple thing example
type SimpleThingExample struct {
	anvil.NopSetupCleanup
}

func (t *SimpleThingExample) Setup(state anvil.TestState) (data anvil.ThingData, ok bool) {
	var verifier jose.JSONWebKey
	err := verifier.UnmarshalJSON([]byte(thingJWK))
	if err != nil {
		anvil.DebugLogger.Println("failed to create confirmation key", err)
		return data, false
	}
	data.Id.ThingKeys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{verifier}}
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
	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/simple/thing",
		"-url", am.AMURL,
		"-realm", fmt.Sprintf("%s", state.Realm()),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-server", server,
		"-address", iecAddress)

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
	var verifier jose.JSONWebKey
	err := verifier.UnmarshalJSON([]byte(thingJWK))
	if err != nil {
		anvil.DebugLogger.Println("failed to create confirmation key", err)
		return data, false
	}
	data.Id.ThingKeys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{verifier}}
	data.Id.ThingType = things.TypeIEC
	return anvil.CreateIdentity(state.Realm(), data)
}

func (t *SimpleIECExample) Run(state anvil.TestState, data anvil.ThingData) bool {
	switch state.InitClients(jwtPopAuthTree).(type) {
	case *things.IECClient:
		// as this example involves an IEC there is no benefit of running it again during the IEC test set
		return true
	}

	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/simple/iec",
		"-url", am.AMURL,
		"-realm", fmt.Sprintf("%s", state.Realm()),
		"-tree", jwtPopAuthTree,
		"-name", data.Id.Name,
		"-address", ":0")

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
