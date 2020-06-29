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
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/tokencache"
	"github.com/dchest/uniuri"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"io"
	"testing"
	"time"
)

// mockClient mocks a thing.mockClient
type mockClient struct {
	AuthenticateFunc func(authenticatePayload) (authenticatePayload, error)
	amInfoFunc       func() (amInfoSet, error)
	amInfoSet        amInfoSet
	accessTokenFunc  func(string, string) ([]byte, error)
	attributesFunc   func(string, string, []string) ([]byte, error)
}

func (m *mockClient) initialise() error {
	m.amInfoSet = amInfoSet{
		AccessTokenURL: "/things",
		ThingsVersion:  "1",
	}
	return nil
}

func (m *mockClient) authenticate(payload authenticatePayload) (reply authenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenId = uniuri.New()
	return reply, nil
}

func (m *mockClient) amInfo() (info amInfoSet, err error) {
	if m.amInfoFunc != nil {
		return m.amInfoFunc()
	}
	return m.amInfoSet, nil
}

func (m *mockClient) accessToken(tokenID string, _ contentType, payload string) (reply []byte, err error) {
	if m.accessTokenFunc != nil {
		return m.accessTokenFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}

func (m *mockClient) attributes(tokenID string, _ contentType, payload string, names []string) (reply []byte, err error) {
	if m.attributesFunc != nil {
		return m.attributesFunc(tokenID, payload, names)
	}
	return []byte("{}"), nil
}

func testGateway(client *mockClient) *ThingGateway {
	return &ThingGateway{
		Thing:     Thing{connection: client},
		authCache: tokencache.New(5*time.Minute, 10*time.Minute),
	}

}

// check that the Auth Id Key is not sent to AM
func TestGateway_Authenticate_AuthIdKey_Is_Not_Sent(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(payload authenticatePayload) (reply authenticatePayload, err error) {
			if payload.AuthIDKey != "" {
				return reply, fmt.Errorf("don't send auth id digest")
			}
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, err := gateway.authenticate(authenticatePayload{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.authenticate(reply)
	if err != nil {
		t.Fatal(err)
	}
}

// check that the Auth Id is not returned by the Thing Gateway to the Thing
func TestGateway_Authenticate_AuthId_Is_Not_Returned(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ authenticatePayload) (reply authenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(authenticatePayload{})
	if reply.AuthId != "" {
		t.Fatal("AuthId has been returned")
	}
}

// check that the Auth Id is cached by the Thing Gateway
func TestGateway_Authenticate_AuthId_Is_Cached(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ authenticatePayload) (reply authenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(authenticatePayload{})
	id, ok := gateway.authCache.Get(reply.AuthIDKey)
	if !ok {
		t.Fatal("The authId has not been stored")
	}
	if id != authId {
		t.Error("The stored authId is not correct")
	}
}

func testDial(client *coap.Client) error {
	gateway := testGateway(&mockClient{})
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	conn, err := client.Dial(gateway.Address())
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func TestGatewayServer_Dial(t *testing.T) {
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

func TestGatewayServer_Dial_BadClientAuth(t *testing.T) {
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

func testGatewayServerAuthenticate(m *mockClient) (err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err = gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = client.initialise()
	if err != nil {
		panic(err)
	}
	_, err = client.authenticate(authenticatePayload{})
	return err
}

func TestGatewayServer_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "auth-error", client: &mockClient{AuthenticateFunc: func(authenticatePayload) (authenticate authenticatePayload, err error) {
			return authenticatePayload{}, errors.New("AM auth error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayServerAuthenticate(subtest.client)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testGatewayServerAMInfo(m *mockClient) (info amInfoSet, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = client.initialise()
	if err != nil {
		panic(err)
	}
	return client.amInfo()
}

func TestGatewayServer_AMInfo(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "endpoint-error", client: &mockClient{amInfoFunc: func() (endpoint amInfoSet, err error) {
			return endpoint, errors.New("AM endpoint info error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			info, err := testGatewayServerAMInfo(subtest.client)
			if subtest.successful {
				if err != nil {
					t.Error(err)
				} else if info != subtest.client.amInfoSet {
					t.Errorf("Expected info %v, got %v", subtest.client.amInfoSet, info)
				}
				return
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testGatewayServerAccessToken(m *mockClient, jws string) (reply []byte, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = client.initialise()
	if err != nil {
		panic(err)
	}
	return client.accessToken("", applicationJOSE, jws)
}

func TestGatewayServer_AccessToken(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
		jws        string
	}{
		{name: "success", successful: true, client: &mockClient{}, jws: ".eyJjc3JmIjoiMTIzNDUifQ."},
		{name: "not-a-valid-jwt", client: &mockClient{}, jws: "eyJjc3JmIjoiMTIzNDUifQ"},
		{name: "am-client-returns-error", jws: ".eyJjc3JmIjoiMTIzNDUifQ.", client: &mockClient{accessTokenFunc: func(string, string) (bytes []byte, err error) {
			return nil, errors.New("AM access token error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			_, err := testGatewayServerAccessToken(subtest.client, subtest.jws)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func TestGatewayServer_Address(t *testing.T) {
	gateway := testGateway(&mockClient{})
	// before the server has started, the address is the empty string
	if gateway.Address() != "" {
		t.Errorf("Thing Gateway has CoAP address %s before it is started", gateway.Address())
	}

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		t.Fatal(err)
	}
	l, ok := gateway.coapServer.Listener.(*net.DTLSListener)
	if !ok {
		t.Errorf("expected type *net.DTLSListener but got %T", gateway.coapServer.Listener)
	}
	if gateway.Address() != l.Addr().String() {
		t.Errorf("Expected CoAP address %s, got %s", l.Addr().String(), gateway.Address())

	}

	gateway.ShutdownCOAPServer()
	// after the server has started, the address is the empty string
	if gateway.Address() != "" {
		t.Errorf("Thing Gateway has CoAP address %s after it was stopped", gateway.Address())
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

func TestGateway_StartCOAPServer(t *testing.T) {
	gateway := testGateway(&mockClient{})

	// try to start the server without a key
	err := gateway.StartCOAPServer(":0", nil)
	if err == nil {
		t.Error("Expected an error")
	}

	// use a bad signer
	err = gateway.StartCOAPServer(":0", testBadSigner{})
	if err == nil {
		t.Error("Expected an error")
	}

	// start server properly
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = gateway.StartCOAPServer(":0", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.ShutdownCOAPServer()

	// create client to ensure that the connection is up
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = client.initialise()
	if err != nil {
		t.Fatal(err)
	}

	// try to start the server again
	err = gateway.StartCOAPServer(gateway.Address(), serverKey)
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

func TestGateway_ShutdownCOAPServer(t *testing.T) {
	t.Skip("Finaliser issue")
	gateway := testGateway(&mockClient{})
	// try to stop the server before it is started, it should fail silently
	gateway.ShutdownCOAPServer()

	// start server
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err := gateway.StartCOAPServer(":0", serverKey)
	if err != nil {
		t.Fatal(err)
	}
	// create client to ensure that the connection is up
	clientKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client1 := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = client1.initialise()
	// shutdown server
	gateway.ShutdownCOAPServer()
	if err != nil {
		t.Fatal(err)
	}
	client1.conn.Close()

	client2 := &gatewayConnection{address: gateway.Address(), key: clientKey}
	err = testTimeout(10*time.Millisecond, client2.initialise)
	if err == nil {
		t.Error("Expected an error")
	}
	err = client1.initialise()
}
