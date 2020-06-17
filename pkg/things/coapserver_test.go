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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"io"
	"testing"
	"time"
)

func testDial(client *coap.Client) error {
	iec := testIEC(&mockClient{})
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer iec.ShutdownCOAPServer()

	conn, err := client.Dial(iec.Address())
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func TestCOAPServer_Dial(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := publicKeyCertificate(key)
	client := &coap.Client{Net: "udp-dtls", DTLSConfig: dtlsClientConfig(cert)}
	if err := testDial(client); err != nil {
		t.Error(err)
	}
}

func testWrongTLSSigner() tls.Certificate {
	right, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cert, err := publicKeyCertificate(right)
	if err != nil {
		panic(err)
	}

	cert.PrivateKey = wrong
	return cert
}

func TestCOAPServer_Dial_BadClientAuth(t *testing.T) {
	tests := []struct {
		name   string
		config *dtls.Config
	}{
		{name: "no-cert", config: dtlsClientConfig()},
		{name: "wrong-tls-signer", config: dtlsClientConfig(testWrongTLSSigner())},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			coapClient := &coap.Client{Net: "udp-dtls", DTLSConfig: subtest.config}
			if testDial(coapClient) == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}

func testCOAPServerAuthenticate(m *mockClient) (err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iec := testIEC(m)
	if err = iec.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer iec.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &IECClient{Address: iec.Address(), Key: clientKey}
	err = client.Initialise()
	if err != nil {
		panic(err)
	}
	_, err = client.Authenticate(AuthenticatePayload{})
	return err
}

func TestCOAPServer_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "auth-error", client: &mockClient{AuthenticateFunc: func(AuthenticatePayload) (authenticate AuthenticatePayload, err error) {
			return AuthenticatePayload{}, errors.New("AM auth error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testCOAPServerAuthenticate(subtest.client)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testCOAPServerAMInfo(m *mockClient) (info AMInfoSet, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iec := testIEC(m)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer iec.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &IECClient{Address: iec.Address(), Key: clientKey}
	err = client.Initialise()
	if err != nil {
		panic(err)
	}
	return client.AMInfo()
}

func TestCOAPServer_AMInfo(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "endpoint-error", client: &mockClient{amInfoFunc: func() (endpoint AMInfoSet, err error) {
			return endpoint, errors.New("AM endpoint info error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			info, err := testCOAPServerAMInfo(subtest.client)
			if subtest.successful {
				if err != nil {
					t.Error(err)
				} else if info != subtest.client.amInfo {
					t.Errorf("Expected info %v, got %v", subtest.client.amInfo, info)
				}
				return
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testCOAPServerSendCommand(m *mockClient, jws string) (reply []byte, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	iec := testIEC(m)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer iec.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &IECClient{Address: iec.Address(), Key: clientKey}
	err = client.Initialise()
	if err != nil {
		panic(err)
	}
	return client.SendCommand("", jws)
}

func TestCOAPServer_SendCommand(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
		jws        string
	}{
		{name: "success", successful: true, client: &mockClient{}, jws: ".eyJjc3JmIjoiMTIzNDUifQ."},
		{name: "not-a-valid-jwt", client: &mockClient{}, jws: "eyJjc3JmIjoiMTIzNDUifQ"},
		{name: "am-client-returns-error", jws: ".eyJjc3JmIjoiMTIzNDUifQ.", client: &mockClient{sendCommandFunc: func(string, string) (bytes []byte, err error) {
			return nil, errors.New("AM send command error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			_, err := testCOAPServerSendCommand(subtest.client, subtest.jws)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func TestIEC_Address(t *testing.T) {
	iec := testIEC(&mockClient{})
	// before the server has started, the address is the empty string
	if iec.Address() != "" {
		t.Errorf("IEC has CoAP address %s before it is started", iec.Address())
	}

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := iec.StartCOAPServer(":0", serverKey); err != nil {
		t.Fatal(err)
	}
	l, ok := iec.coapServer.Listener.(*net.DTLSListener)
	if !ok {
		t.Errorf("expected type *net.DTLSListener but got %T", iec.coapServer.Listener)
	}
	if iec.Address() != l.Addr().String() {
		t.Errorf("Expected CoAP address %s, got %s", l.Addr().String(), iec.Address())

	}

	iec.ShutdownCOAPServer()
	// after the server has started, the address is the empty string
	if iec.Address() != "" {
		t.Errorf("IEC has CoAP address %s after it was stopped", iec.Address())
	}
}

type testBadSigner struct {
}

func (_ testBadSigner) Public() crypto.PublicKey {
	return 1
}

func (_ testBadSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return nil, errors.New("i haven't a pen")
}

func TestIEC_StartCOAPServer(t *testing.T) {
	iec := testIEC(&mockClient{})

	// try to start the server without a key
	err := iec.StartCOAPServer(":0", nil)
	if err == nil {
		t.Error("Expected an error")
	}

	// use a bad signer
	err = iec.StartCOAPServer(":0", testBadSigner{})
	if err == nil {
		t.Error("Expected an error")
	}

	// start server properly
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = iec.StartCOAPServer(":0", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer iec.ShutdownCOAPServer()

	// create client to ensure that the connection is up
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &IECClient{Address: iec.Address(), Key: clientKey}
	err = client.Initialise()
	if err != nil {
		t.Fatal(err)
	}

	// try to start the server again
	err = iec.StartCOAPServer(iec.Address(), serverKey)
	if err == nil {
		t.Error("Expected an error")
	}
}

func testTimeout(timeout time.Duration, f func() error) error {
	timer := time.After(timeout)
	done := make(chan error)
	go func() {
		done <- f()
	}()

	select {
	case <-timer:
		return errors.New("timer")
	case err := <-done:
		return err
	}
}

func TestIEC_ShutdownCOAPServer(t *testing.T) {
	t.Skip("Finaliser issue")
	iec := testIEC(&mockClient{})
	// try to stop the server before it is started, it should fail silently
	iec.ShutdownCOAPServer()

	// start server
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := iec.StartCOAPServer(":0", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	// create client to ensure that the connection is up
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client1 := &IECClient{Address: iec.Address(), Key: clientKey}
	err = client1.Initialise()
	// shutdown server
	iec.ShutdownCOAPServer()
	if err != nil {
		t.Fatal(err)
	}
	client1.conn.Close()

	client2 := &IECClient{Address: iec.Address(), Key: clientKey}
	err = testTimeout(10*time.Millisecond, client2.Initialise)
	if err == nil {
		t.Error("Expected an error")
	}
	err = client1.Initialise()
}
