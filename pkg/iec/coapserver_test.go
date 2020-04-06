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
	"context"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/mock"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"golang.org/x/sync/errgroup"
	"testing"
)

const (
	address  = "127.0.0.1:5688"
	testTree = "testTree"
)

func TestCOAPServer_Initialise(t *testing.T) {
	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	if err := iec.StartCOAPServer(address); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	err := things.NewCOAPClient(address).Initialise()
	if err != nil {
		t.Error(err)
	}
}

func authSimpleClient(name string) error {
	c := things.NewCOAPClient(address)
	err := c.Initialise()
	if err != nil {
		return fmt.Errorf("%s %s", name, err)
	}

	handlers := []message.CallbackHandler{message.NameCallbackHandler{Name: name}}
	var payload message.AuthenticatePayload
	for i := 0; i < 5; i++ {
		payload, err = c.Authenticate(mock.SimpleTestAuthTree, payload)
		if err != nil {
			return fmt.Errorf("%s %s", name, err)
		}

		// check that the reply has a token
		if payload.HasSessionToken() {
			return nil
		}

		err = message.ProcessCallbacks(payload.Callbacks, handlers)
		if err != nil {
			return fmt.Errorf("%s %s", name, err)
		}
	}
	return fmt.Errorf("%s got stuck in a loop", name)
}

func TestCOAPServer_Authenticate(t *testing.T) {
	am := mock.NewSimpleServer().Start("127.0.0.1:8008")
	defer am.Close()

	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	if err := iec.StartCOAPServer(address); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	err := authSimpleClient("test-client")
	if err != nil {
		t.Fatal(err)
	}
}

// checks that the IEC can authenticate multiple client concurrently
func TestCOAPServer_Authenticate_Multiple(t *testing.T) {
	am := mock.NewSimpleServer().Start("127.0.0.1:8008")
	defer am.Close()

	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	if err := iec.StartCOAPServer(address); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	errGroup, _ := errgroup.WithContext(context.Background())
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("client%d", i)
		errGroup.Go(func() error {
			return authSimpleClient(name)
		})
	}
	err := errGroup.Wait()
	if err != nil {
		t.Fatal(err)
	}
}
