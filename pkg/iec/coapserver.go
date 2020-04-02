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
	"encoding/json"
	"errors"
	"github.com/ForgeRock/iot-edge/pkg/message"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
)

// ErrCOAPServerAlreadyStarted indicates that a COAP server has already been started by the IEC
var ErrCOAPServerAlreadyStarted = errors.New("COAP server has already been started")

// temporary variable until IOTEDGE-908
var authID string

// authenticateHandler handles authentication requests
func (c *IEC) authenticateHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("authenticateHandler")
	// check that the query is set to auth tree
	query := r.Msg.Query()
	if len(query) != 1 {
		DebugLogger.Println("Missing or incorrect auth tree")
		w.SetCode(codes.BadRequest)
		w.Write([]byte("Missing or incorrect auth tree"))
		return
	}
	payload := message.AuthenticatePayload{AuthID: authID}
	if err := json.Unmarshal(r.Msg.Payload(), &payload); err != nil {
		DebugLogger.Printf("Unable to unmarshall payload; %s", err)
		w.SetCode(codes.BadRequest)
		w.Write([]byte("Unable to unmarshall payload"))
		return
	}

	reply, err := c.Authenticate(query[0], payload)
	if err != nil {
		DebugLogger.Printf("Error connecting to AM; %s", err)
		w.SetCode(codes.Unauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	// remove Auth ID as it is usually too big for a single UDP message
	authID = reply.AuthID
	reply.AuthID = ""

	b, err := json.Marshal(reply)
	if err != nil {
		DebugLogger.Printf("Error marshalling Auth Payload; %s", err)
		w.SetCode(codes.Unauthorized)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Valid)
	w.Write(b)
	DebugLogger.Println("authenticateHandler: success")
}

// StartCOAPServer starts a COAP server within the IEC
func (c *IEC) StartCOAPServer(address string) error {
	if c.coapServer != nil {
		return ErrCOAPServerAlreadyStarted
	}
	c.coapChan = make(chan error, 1)
	mux := coap.NewServeMux()
	mux.HandleFunc("/authenticate", c.authenticateHandler)
	// use UDP as default unless the protocol has been configured
	net := "udp"
	if c.Net != "" {
		net = c.Net
	}
	c.coapServer = &coap.Server{Addr: address, Net: net, Handler: mux}
	go func() {
		c.coapChan <- c.coapServer.ListenAndServe()
		c.coapServer = nil
	}()
	return nil
}

// ShutdownCOAPServer gracefully shuts the COAP server down
func (c *IEC) ShutdownCOAPServer() {
	if c.coapServer == nil {
		return
	}
	c.coapServer.Shutdown()
	// wait for shutdown to complete
	<-c.coapChan
}
