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
	"encoding/json"
	"errors"
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
)

// CoAP server design
// CoAP method is taken from the HTTP method used to communicate with AM
// The CoAP response status codes follow the CoAP-HTTP proxy guidance in the CoAP specification
// https://tools.ietf.org/html/rfc7252#section-10.1

// ErrCOAPServerAlreadyStarted indicates that a COAP server has already been started by the IEC
var ErrCOAPServerAlreadyStarted = errors.New("COAP server has already been started")

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
	var auth payload.Authenticate
	if err := json.Unmarshal(r.Msg.Payload(), &auth); err != nil {
		DebugLogger.Printf("Unable to unmarshall payload; %s", err)
		w.SetCode(codes.BadRequest)
		w.Write([]byte("Unable to unmarshall payload"))
		return
	}

	reply, err := c.Authenticate(query[0], auth)
	if err != nil {
		DebugLogger.Printf("Error connecting to AM; %s", err)
		w.SetCode(codes.Unauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	b, err := json.Marshal(reply)
	if err != nil {
		DebugLogger.Printf("Error marshalling Auth Payload; %s", err)
		w.SetCode(codes.BadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Valid)
	w.Write(b)
	DebugLogger.Println("authenticateHandler: success")
}

// iotEndpointInfoHandler handles IoT Endpoint Info requests
func (c *IEC) iotEndpointInfoHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("iotEndpointInfoHandler")
	info, err := c.Client.IoTEndpointInfo()
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		w.Write([]byte(""))
		return
	}
	b, err := json.Marshal(info)
	if err != nil {
		DebugLogger.Printf("Error marshalling IoTEndpointInfo; %s", err)
		w.SetCode(codes.BadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Content)
	w.Write(b)
	DebugLogger.Println("iotEndpointInfoHandler: success")
}

// sendCommandHandler handles Send Command requests
func (c *IEC) sendCommandHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("sendCommandHandler")
	payload := string(r.Msg.Payload())
	// get SSO token from the CSRF claim in the JWT
	var claims sendCommandClaims
	err := extractJWTPayload(payload, &claims)
	if err != nil {
		w.SetCode(codes.BadRequest)
		w.Write([]byte("Can't parse signed JWT"))
		return
	}

	b, err := c.Client.SendCommand(claims.CSRF, payload)
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	w.Write(b)
	DebugLogger.Println("sendCommandHandler: success")
}

// StartCOAPServer starts a COAP server within the IEC
func (c *IEC) StartCOAPServer(address string) error {
	if c.coapServer != nil {
		return ErrCOAPServerAlreadyStarted
	}
	c.coapChan = make(chan error, 1)
	mux := coap.NewServeMux()
	mux.HandleFunc("/authenticate", c.authenticateHandler)
	mux.HandleFunc("/iotendpointinfo", c.iotEndpointInfoHandler)
	mux.HandleFunc("/sendcommand", c.sendCommandHandler)
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
