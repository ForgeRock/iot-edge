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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"golang.org/x/sync/errgroup"
	"testing"
)

func testGenerateSigner() crypto.Signer {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return key
}

func testAuthCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/authenticate", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		w.Write(response)
		return
	})
	return mux
}

func testAMInfoCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/aminfo", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		w.Write(response)
		return
	})
	return mux
}

func testSendCommandCOAPMux(code codes.Code, response []byte) (mux *coap.ServeMux) {
	mux = coap.NewServeMux()
	mux.HandleFunc("/sendcommand", func(w coap.ResponseWriter, r *coap.Request) {
		w.SetCode(code)
		w.Write(response)
		return
	})
	return mux
}

type testCOAPServer struct {
	config *dtls.Config
	mux    *coap.ServeMux
}

func (s testCOAPServer) Start() (address string, cancel func(), err error) {
	l, err := net.NewDTLSListener("udp", ":0", s.config, HeartBeat)
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
		server.Shutdown()
		<-c
	}, nil
}

func testIECClientInitialise(client *IECClient, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.Address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	return client.Initialise()
}

func TestIECClient_Initialise(t *testing.T) {
	cert, _ := publicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *IECClient
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &IECClient{Key: testGenerateSigner()}, server: &testCOAPServer{config: dtlsServerConfig(cert), mux: coap.DefaultServeMux}},
		{name: "client-no-signer", client: &IECClient{Key: nil}, server: nil},
		// starting a DTLS server without a certificate or PSK is an error.
		{name: "server-wrong-tls-signer", client: &IECClient{Key: testGenerateSigner()}, server: &testCOAPServer{config: dtlsServerConfig(testWrongTLSSigner()), mux: coap.DefaultServeMux}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testIECClientInitialise(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

// checks that multiple IECClients can be initialised concurrently
func TestIECClient_Initialise_Concurrent(t *testing.T) {
	t.Skip("Concurrent DTLS handshakes fail")

	cert, _ := publicKeyCertificate(testGenerateSigner())
	addr, cancel, err := testCOAPServer{config: dtlsServerConfig(cert), mux: coap.DefaultServeMux}.Start()
	defer cancel()
	if err != nil {
		t.Fatal(err)
	}

	errGroup, _ := errgroup.WithContext(context.Background())
	const num = 5
	for i := 0; i < num; i++ {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		client := NewIECClient(addr, key)
		errGroup.Go(func() error {
			return client.Initialise()
		})
	}
	err = errGroup.Wait()
	if err != nil {
		t.Fatal(err)
	}
}

func testIECClientAuthenticate(client *IECClient, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.Address, cancel, err = server.Start()
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

func TestIECClient_Authenticate(t *testing.T) {
	info := AuthenticatePayload{
		TokenId: "12345",
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := publicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *IECClient
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.Valid, b)}},
		{name: "unexpected-code", client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.BadGateway, b)}},
		{name: "invalid-auth-payload", client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAuthCOAPMux(codes.Content, []byte("aaaa"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testIECClientAuthenticate(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testIECClientAMInfo(client *IECClient, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.Address, cancel, err = server.Start()
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

func TestIECClient_AMInfo(t *testing.T) {
	info := AMInfoSet{
		IoTURL:     "/iot",
		IoTVersion: "1",
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	cert, _ := publicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *IECClient
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.Content, b)}},
		{name: "unexpected-code", client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.BadGateway, b)}},
		{name: "invalid-info", client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testAMInfoCOAPMux(codes.Content, []byte("aaaa"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testIECClientAMInfo(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testIECClientSendCommand(client *IECClient, server *testCOAPServer) (err error) {
	if server != nil {
		var cancel func()
		client.Address, cancel, err = server.Start()
		if err != nil {
			panic(err)
		}
		defer cancel()
	}

	err = client.Initialise()
	if err != nil {
		return err
	}
	_, err = client.SendCommand("token", "signedWT")
	return err
}

func TestIECClient_SendCommand(t *testing.T) {
	cert, _ := publicKeyCertificate(testGenerateSigner())

	tests := []struct {
		name       string
		successful bool
		client     *IECClient
		server     *testCOAPServer
	}{
		{name: "success", successful: true, client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testSendCommandCOAPMux(codes.Changed, []byte("{}"))}},
		{name: "unexpected-code", client: &IECClient{Key: testGenerateSigner()},
			server: &testCOAPServer{config: dtlsServerConfig(cert), mux: testSendCommandCOAPMux(codes.BadGateway, []byte("{}"))}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testIECClientSendCommand(subtest.client, subtest.server)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}
