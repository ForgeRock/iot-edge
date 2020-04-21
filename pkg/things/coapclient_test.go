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
	"crypto/tls"
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"golang.org/x/sync/errgroup"
	"testing"
	"time"
)

func startTestServer() (address string, cancel func(), err error) {
	mux := coap.NewServeMux()
	mux.HandleFunc("/authenticate", func(w coap.ResponseWriter, r *coap.Request) {
		// check that the query is set to auth tree
		query := r.Msg.Query()
		if len(query) != 1 || query[0] != testTree {
			w.SetCode(codes.BadRequest)
			w.Write([]byte("Missing or incorrect auth tree"))
			return
		}
		w.SetCode(codes.Valid)
		// just echo the payload back
		w.Write(r.Msg.Payload())
	})
	c := make(chan error, 1)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert, _ := publicKeyCertificate(key)
	l, err := net.NewDTLSListener("udp", ":0",
		&dtls.Config{
			Certificates:         []tls.Certificate{cert},
			ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		},
		time.Millisecond*100)
	if err != nil {
		return "", func() {}, err
	}
	server := &coap.Server{
		Listener: l,
		Handler:  mux,
	}
	go func() {
		c <- server.ActivateAndServe()
		l.Close()
	}()
	return l.Addr().String(), func() {
		server.Shutdown()
		<-c
	}, nil
}

func TestCOAPClient_Initialise(t *testing.T) {
	addr, cancel, err := startTestServer()
	defer cancel()
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := NewIECClient(addr, key)
	err = client.Initialise()
	if err != nil {
		t.Error(err)
	}
}

// checks that multiple IECClients can be initialised concurrently
func TestCOAPClient_Initialise_Concurrent(t *testing.T) {
	t.Skip("Concurrent DTLS handshakes fail")
	addr, cancel, err := startTestServer()
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

func TestCOAPClient_Authenticate(t *testing.T) {
	addr, cancel, err := startTestServer()
	defer cancel()
	if err != nil {
		t.Fatal(err)
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := NewIECClient(addr, key)
	err = client.Initialise()
	if err != nil {
		t.Fatal(err)
	}
	auth := payload.Authenticate{
		TokenId:   "",
		AuthId:    "12345",
		Callbacks: nil,
	}
	reply, err := client.Authenticate(testTree, auth)
	if err != nil {
		t.Fatal(err)
	}
	if auth.AuthId != reply.AuthId {
		t.Error("Expected the authentication payload echoed back to the caller")
	}
}
