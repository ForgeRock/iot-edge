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

package gateway

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/url"
	"testing"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/ForgeRock/iot-edge/v7/internal/introspect"
	"github.com/ForgeRock/iot-edge/v7/internal/tokencache"
	"github.com/dchest/uniuri"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
)

// mockClient mocks a thing.mockClient
type mockClient struct {
	AuthenticateFunc func(client.AuthenticatePayload) (client.AuthenticatePayload, error)
	amInfoFunc       func() (client.AMInfoResponse, error)
	amInfoSet        client.AMInfoResponse
	accessTokenFunc  func(string, string) ([]byte, error)
	attributesFunc   func(string, string, []string) ([]byte, error)
}

func (m *mockClient) ValidateSession(tokenID string) (ok bool, err error) {
	return true, nil
}

func (m *mockClient) LogoutSession(tokenID string) (err error) {
	return nil
}

func (m *mockClient) Initialise() error {
	m.amInfoSet = client.AMInfoResponse{
		AccessTokenURL: "/things",
		ThingsVersion:  "1",
	}
	return nil
}

func (m *mockClient) Authenticate(payload client.AuthenticatePayload) (reply client.AuthenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenID = uniuri.New()
	return reply, nil
}

func (m *mockClient) AMInfo() (info client.AMInfoResponse, err error) {
	if m.amInfoFunc != nil {
		return m.amInfoFunc()
	}
	return m.amInfoSet, nil
}

func (m *mockClient) AccessToken(tokenID string, _ client.ContentType, payload string) (reply []byte, err error) {
	if m.accessTokenFunc != nil {
		return m.accessTokenFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}

func (m *mockClient) IntrospectAccessToken(token string) (introspection []byte, err error) {
	return introspect.InactiveIntrospectionBytes, nil
}

func (m *mockClient) Attributes(tokenID string, _ client.ContentType, payload string, names []string) (reply []byte, err error) {
	if m.attributesFunc != nil {
		return m.attributesFunc(tokenID, payload, names)
	}
	return []byte("{}"), nil
}

func testGateway(client *mockClient) *ThingGateway {
	return &ThingGateway{
		amConnection: client,
		authCache:    tokencache.New(5*time.Minute, 10*time.Minute),
	}

}

// check that the Auth Id Key is not sent to AM
func TestGateway_Authenticate_AuthIdKey_Is_Not_Sent(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(payload client.AuthenticatePayload) (reply client.AuthenticatePayload, err error) {
			if payload.AuthIDKey != "" {
				return reply, fmt.Errorf("don't send auth id digest")
			}
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, err := gateway.authenticate(client.AuthenticatePayload{})
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
		AuthenticateFunc: func(_ client.AuthenticatePayload) (reply client.AuthenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(client.AuthenticatePayload{})
	if reply.AuthId != "" {
		t.Fatal("AuthId has been returned")
	}
}

// check that the Auth Id is cached by the Thing Gateway
func TestGateway_Authenticate_AuthId_Is_Cached(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ client.AuthenticatePayload) (reply client.AuthenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(client.AuthenticatePayload{})
	id, ok := gateway.authCache.Get(reply.AuthIDKey)
	if !ok {
		t.Fatal("The authId has not been stored")
	}
	if id != authId {
		t.Error("The stored authId is not correct")
	}
}

func testDial(coapClient *coap.Client) error {
	gateway := testGateway(&mockClient{})
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	conn, err := coapClient.Dial(gateway.Address())
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

func dtlsClientConfig(cert ...tls.Certificate) *dtls.Config {
	return &dtls.Config{
		Certificates:         cert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		InsecureSkipVerify:   true,
	}
}

func TestGatewayServer_Dial(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := frcrypto.PublicKeyCertificate(key)
	coapClient := &coap.Client{Net: "udp-dtls", DTLSConfig: dtlsClientConfig(cert)}
	if err := testDial(coapClient); err != nil {
		t.Error(err)
	}
}

func testWrongTLSSigner() tls.Certificate {
	right, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrong, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	cert, err := frcrypto.PublicKeyCertificate(right)
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

func testGatewayServerAuthenticate(t *testing.T, m *mockClient) (err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err = gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	_, err = gatewayConnection(t, gateway).Authenticate(client.AuthenticatePayload{})
	return err
}

func TestGatewayServer_Authenticate(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "auth-error", client: &mockClient{AuthenticateFunc: func(client.AuthenticatePayload) (authenticate client.AuthenticatePayload, err error) {
			return client.AuthenticatePayload{}, errors.New("AM auth error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayServerAuthenticate(t, subtest.client)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testGatewayServerAMInfo(t *testing.T, m *mockClient) (info client.AMInfoResponse, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	return gatewayConnection(t, gateway).AMInfo()
}

func TestGatewayServer_AMInfo(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		client     *mockClient
	}{
		{name: "success", successful: true, client: &mockClient{}},
		{name: "endpoint-error", client: &mockClient{amInfoFunc: func() (endpoint client.AMInfoResponse, err error) {
			return endpoint, errors.New("AM endpoint info error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			info, err := testGatewayServerAMInfo(t, subtest.client)
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

func testGatewayServerAccessToken(t *testing.T, m *mockClient, jws string) (reply []byte, err error) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gateway := testGateway(m)
	if err := gateway.StartCOAPServer(":0", serverKey); err != nil {
		panic(err)
	}
	defer gateway.ShutdownCOAPServer()

	return gatewayConnection(t, gateway).AccessToken("", client.ApplicationJOSE, jws)
}

func TestGatewayServer_AccessToken(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		connection *mockClient
		jws        string
	}{
		{name: "success", successful: true, connection: &mockClient{}, jws: ".eyJjc3JmIjoiMTIzNDUifQ."},
		{name: "not-a-valid-jwt", connection: &mockClient{}, jws: "eyJjc3JmIjoiMTIzNDUifQ"},
		{name: "am-client-returns-error", jws: ".eyJjc3JmIjoiMTIzNDUifQ.", connection: &mockClient{accessTokenFunc: func(string, string) (bytes []byte, err error) {
			return nil, errors.New("AM access token error")
		}}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			_, err := testGatewayServerAccessToken(t, subtest.connection, subtest.jws)
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
	gatewayConnection(t, gateway)

	// try to start the server again
	err = gateway.StartCOAPServer(gateway.Address(), serverKey)
	if err == nil {
		t.Error("Expected an error")
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
	gatewayConnection(t, gateway)
	// shutdown server
	gateway.ShutdownCOAPServer()
	if err != nil {
		t.Fatal(err)
	}

	gwURL, _ := url.Parse("coap://" + gateway.Address())
	connBuilder := client.NewConnection().
		ConnectTo(gwURL).
		WithKey(clientKey)

	timer := time.After(10 * time.Millisecond)
	done := make(chan error)
	go func() {
		_, err := connBuilder.Create()
		done <- err
	}()

	select {
	case <-timer:
		err = errors.New("timer")
	case err = <-done:
	}
	if err == nil {
		t.Error("Expected an error")
	}
}

var clientKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

func gatewayConnection(t *testing.T, gateway *ThingGateway) client.Connection {
	gwURL, _ := url.Parse("coap://" + gateway.Address())
	connection, err := client.NewConnection().
		ConnectTo(gwURL).
		WithKey(clientKey).
		Create()
	if err != nil {
		t.Fatal(err)
	}
	return connection
}
