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

package client

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"golang.org/x/sync/errgroup"
)

func dtlsServerConfig(cert ...tls.Certificate) *dtls.Config {
	return &dtls.Config{
		Certificates:         cert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.RequireAnyClientCert,
	}
}

func testGenerateSigner() crypto.Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func testAuthCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/authenticate", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		_, _ = w.Write(response)
	})
	return mux
}

func testAMInfoCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/aminfo", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		_, _ = w.Write(response)
	})
	return mux
}

func testAccessTokenCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/accesstoken", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		_, _ = w.Write(response)
	})
	return mux
}

type testCOAPServer struct {
	config *dtls.Config
	mux    *coap.ServeMux
}

func (s testCOAPServer) Start() (address string, cancel func(), err error) {
	l, err := net.NewDTLSListener("udp", ":0", s.config, time.Millisecond*100)
	if err != nil {
		return "", func() {}, err
	}
	server := &coap.Server{
		Listener: l,
		Handler:  s.mux,
	}
	c := make(chan error, 1)
	go func() {
		c <- server.ActivateAndServe()
		l.Close()
	}()
	return l.Addr().String(), func() {
		if err := server.Shutdown(); err != nil {
			return
		}
		<-c
	}, nil
}

func testGatewayClientInitialise(client *gatewayConnection, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	return client.Initialise()
}

func TestGatewayClient_Initialise(t *testing.T) {
	cert, _ := frcrypto.PublicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *gatewayConnection
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: coap.DefaultServeMux}},
		{name: "client-no-signer", client: &gatewayConnection{key: nil}, server: nil},
		// starting a DTLS server without a certificate or PSK is an error.
		{name: "server-wrong-tls-signer", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(testWrongTLSSigner()), mux: coap.DefaultServeMux}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayClientInitialise(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

// checks that multiple Thing Gateway Clients can be initialised concurrently
func TestGatewayClient_Initialise_Concurrent(t *testing.T) {
	t.Skip("Concurrent DTLS handshakes fail")

	cert, _ := frcrypto.PublicKeyCertificate(testGenerateSigner())
	addr, cancel, err := testCOAPServer{config: dtlsServerConfig(cert), mux: coap.DefaultServeMux}.Start()
	defer cancel()
	if err != nil {
		t.Fatal(err)
	}

	errGroup, _ := errgroup.WithContext(context.Background())
	const num = 5
	for i := 0; i < num; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client := &gatewayConnection{
			address: addr,
			key:     key,
		}
		errGroup.Go(func() error {
			return client.Initialise()
		})
	}
	err = errGroup.Wait()
	if err != nil {
		t.Fatal(err)
	}
}

func testGatewayClientAuthenticate(client *gatewayConnection, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	err = client.Initialise()
	if err != nil {
		return err
	}
	_, err = client.Authenticate(AuthenticatePayload{})
	return err
}

func TestGatewayClient_Authenticate(t *testing.T) {
	info := AuthenticatePayload{
		SessionToken: SessionToken{TokenID: "12345"},
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := frcrypto.PublicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *gatewayConnection
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.Valid, b)}},
		{name: "unexpected-code", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.BadGateway, b)}},
		{name: "invalid-auth-payload", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.Content, []byte("aaaa"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayClientAuthenticate(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testGatewayClientAMInfo(client *gatewayConnection, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	err = client.Initialise()
	if err != nil {
		return err
	}
	_, err = client.AMInfo()
	return err
}

func TestGatewayClient_AMInfo(t *testing.T) {
	info := AMInfoResponse{
		AccessTokenURL: "/things",
		ThingsVersion:  "1",
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := frcrypto.PublicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *gatewayConnection
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.Content, b)}},
		{name: "unexpected-code", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.BadGateway, b)}},
		{name: "invalid-info", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.Content, []byte("aaaa"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayClientAMInfo(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testGatewayClientAccessToken(client *gatewayConnection, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	err = client.Initialise()
	if err != nil {
		return err
	}
	_, err = client.AccessToken("token", ApplicationJOSE, "signedWT")
	return err
}

func TestGatewayClient_AccessToken(t *testing.T) {
	cert, _ := frcrypto.PublicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *gatewayConnection
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAccessTokenCOAPMux(codes.Changed, []byte("{}"))}},
		{name: "unexpected-code", client: &gatewayConnection{key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAccessTokenCOAPMux(codes.BadGateway, []byte("{}"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testGatewayClientAccessToken(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
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
