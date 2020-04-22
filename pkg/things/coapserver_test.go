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

package things

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/mock"
	"github.com/ForgeRock/iot-edge/pkg/things/callback"
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"golang.org/x/sync/errgroup"
	"testing"
)

const (
	address  = "127.0.0.1:5688"
	testTree = "testTree"
)

func TestCOAPServer_Initialise(t *testing.T) {
	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := NewIECClient(iec.Address(), clientKey)
	err := client.Initialise()
	if err != nil {
		t.Error(err)
	}
}

func authSimple(client *IECClient, name string) (err error) {
	handlers := []callback.Handler{callback.NameHandler{Name: name}}
	var auth payload.Authenticate
	for i := 0; i < 5; i++ {
		auth, err = client.Authenticate(mock.SimpleTestAuthTree, auth)
		if err != nil {
			return fmt.Errorf("auth %d %s %s", i, name, err)
		}

		// check that the reply has a token
		if auth.HasSessionToken() {
			return nil
		}

		err = callback.ProcessCallbacks(auth.Callbacks, handlers)
		if err != nil {
			return fmt.Errorf("%s %s", name, err)
		}
	}
	return fmt.Errorf("%s got stuck in a loop", name)
}

func TestCOAPServer_Authenticate(t *testing.T) {
	am := mock.NewSimpleServer().Start("127.0.0.1:8008")
	defer am.Close()

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := NewIECClient(iec.Address(), clientKey)
	err := client.Initialise()
	if err != nil {
		t.Error(err)
	}
	err = authSimple(client, "test-client")
	if err != nil {
		t.Fatal(err)
	}
}

// checks that the IEC can authenticate multiple client concurrently
func TestCOAPServer_Authenticate_Concurrent(t *testing.T) {
	am := mock.NewSimpleServer().Start("127.0.0.1:8008")
	defer am.Close()

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iec := NewIEC("http://127.0.0.1:8008", mock.SimpleTestRealm)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	const num = 5
	var clients [num]*IECClient
	for i := 0; i < num; i++ {
		clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		clients[i] = NewIECClient(iec.Address(), clientKey)
		err := clients[i].Initialise()
		if err != nil {
			t.Fatal(err)
		}
	}

	errGroup, _ := errgroup.WithContext(context.Background())
	for i, client := range clients {
		name := fmt.Sprintf("client%d", i)
		localClient := client
		errGroup.Go(func() error {
			return authSimple(localClient, name)
		})
	}
	err := errGroup.Wait()
	if err != nil {
		t.Fatal(err)
	}
}
