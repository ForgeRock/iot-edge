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
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"os/exec"
)

var thingJWK = "{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"alg\":\"ES256\"," +
	"\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\"}"

// SimpleThingExample tests the simple thing example
type SimpleThingExample struct {
	anvil.NopSetupCleanup
}

func (t *SimpleThingExample) Setup() (data anvil.ThingData, ok bool) {
	var verifier jose.JSONWebKey
	err := verifier.UnmarshalJSON([]byte(thingJWK))
	if err != nil {
		anvil.DebugLogger.Println("failed to create confirmation key", err)
		return data, false
	}
	data.Id.ThingKeys = jose.JSONWebKeySet{Keys: []jose.JSONWebKey{verifier}}
	data.Id.ThingType = "Device"
	return anvil.CreateIdentity(data)
}

func (t *SimpleThingExample) Run(client things.Client, data anvil.ThingData) bool {
	var server string
	switch client.(type) {
	case *things.AMClient:
		server = "am"
	case *things.IECClient:
		server = "iec"
	}
	cmd := exec.Command("go", "run", "github.com/ForgeRock/iot-edge/examples/simple/thing",
		"-url", am.AMURL,
		"-realm", data.Realm,
		"-tree", "Anvil-User-Pwd",
		"-name", data.Id.Name,
		"-pwd", data.Id.Password,
		"-server", server)
	stdout, _ := cmd.StdoutPipe()
	startErr := cmd.Start()
	output, _ := ioutil.ReadAll(stdout)
	waitErr := cmd.Wait()
	anvil.DebugLogger.Println(string(output))
	if startErr != nil || waitErr != nil {
		anvil.DebugLogger.Println("simple thing example failed\n", startErr, "\n", waitErr)
		return false
	}
	return true
}
