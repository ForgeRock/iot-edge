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

package iec

import (
	"github.com/ForgeRock/iot-edge/internal/amtest"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"io/ioutil"
	"os"
	"testing"
)

const (
	address  = "127.0.0.1:5688"
	testTree = "testTree"
)

func TestMain(m *testing.M) {
	DebugLogger.SetOutput(os.Stdout)
	things.DebugLogger.SetOutput(os.Stdout)
	defer func() {
		DebugLogger.SetOutput(ioutil.Discard)
		things.DebugLogger.SetOutput(ioutil.Discard)
	}()
	os.Exit(m.Run())
}

func TestServer_Initialise(t *testing.T) {
	iec := NewIEC("http://127.0.0.1:8008", amtest.SimpleTestRealm)
	if err := iec.StartCOAPServer("udp", address); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	_, err := things.NewCOAPClient(address).Initialise()
	if err != nil {
		t.Error(err)
	}
}

func TestServer_Authenticate(t *testing.T) {
	am := amtest.NewSimpleServer().Start("127.0.0.1:8008")
	defer am.Close()

	iec := NewIEC("http://127.0.0.1:8008", amtest.SimpleTestRealm)
	if err := iec.StartCOAPServer("udp", address); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	c, err := things.NewCOAPClient(address).Initialise()
	if err != nil {
		t.Fatal(err)
	}

	reply, err := c.Authenticate(amtest.SimpleTestAuthTree, amtest.SimpleAuthPayload)
	if err != nil {
		t.Fatal(err)
	}
	// check that the reply has a token
	if reply.TokenID == "" {
		t.Errorf("Expected an token in reply: %v", reply)
	}
}
