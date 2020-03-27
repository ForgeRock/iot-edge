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
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"io/ioutil"
	"os"
	"testing"
)

const (
	address  = "127.0.0.1:5688"
	testTree = "testTree"
)

func startTestServer() *coap.Server {
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
	server := &coap.Server{Addr: address, Net: "udp", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			panic(err)
		}
	}()
	return server
}

func TestMain(m *testing.M) {
	DebugLogger.SetOutput(os.Stdout)
	defer func() {
		DebugLogger.SetOutput(ioutil.Discard)
	}()
	server := startTestServer()
	defer server.Shutdown()
	os.Exit(m.Run())
}

func TestCOAPClient_Initialise(t *testing.T) {
	client := NewCOAPClient(address)
	_, err := client.Initialise()
	if err != nil {
		t.Error(err)
	}
}

func TestCOAPClient_Authenticate(t *testing.T) {
	client := NewCOAPClient(address)
	_, err := client.Initialise()
	if err != nil {
		t.Fatal(err)
	}
	payload := AuthenticatePayload{
		TokenID:   "",
		AuthID:    "12345",
		Callbacks: nil,
	}
	reply, err := client.Authenticate(testTree, payload)
	if err != nil {
		t.Fatal(err)
	}
	if payload.AuthID != reply.AuthID {
		t.Error("Expected the authentication payload echoed back to the caller")
	}
}
