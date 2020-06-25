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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	"github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"time"
)

// CoAP server design
// CoAP method is taken from the HTTP method used to communicate with AM
// The CoAP response status codes follow the CoAP-HTTP proxy guidance in the CoAP specification
// https://tools.ietf.org/html/rfc7252#section-10.1

// ErrCOAPServerAlreadyStarted indicates that a COAP server has already been started by the Thing Gateway
var ErrCOAPServerAlreadyStarted = errors.New("COAP server has already been started")

var heartBeat time.Duration = time.Millisecond * 100

// authenticateHandler handles authentication requests
func (c *ThingGateway) authenticateHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("authenticateHandler")
	var auth authenticatePayload
	if err := json.Unmarshal(r.Msg.Payload(), &auth); err != nil {
		DebugLogger.Printf("Unable to unmarshall payload; %s", err)
		w.SetCode(codes.BadRequest)
		w.Write([]byte("Unable to unmarshall payload"))
		return
	}

	reply, err := c.authenticate(auth)
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

// amInfoHandler handles AM Info requests
func (c *ThingGateway) amInfoHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("amInfoHandler")
	info, err := c.Thing.Client.amInfo()
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		w.Write([]byte(""))
		return
	}
	b, err := json.Marshal(info)
	if err != nil {
		DebugLogger.Printf("Error marshalling amInfo; %s", err)
		w.SetCode(codes.BadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Content)
	w.Write(b)
	DebugLogger.Println("amInfoHandler: success")
}

func decodeThingEndpointRequest(msg coap.Message) (token string, content contentType, payload string, err error) {
	coapFormat, ok := msg.Option(coap.ContentFormat).(coap.MediaType)
	if !ok {
		return token, content, payload, fmt.Errorf("missing content format")
	}

	switch coapFormat {
	case coap.AppJSON:
		var request thingEndpointPayload
		if err := json.Unmarshal(msg.Payload(), &request); err != nil {
			return token, content, payload, err
		}
		token = request.Token
		content = applicationJSON
		payload = request.Payload
	case appJOSE:
		payload = string(msg.Payload())
		// get SSO token from the CSRF claim in the JWT
		var claims signedRequestClaims
		if err := extractJWTPayload(payload, &claims); err != nil {
			return token, content, payload, err
		}
		token = claims.CSRF
		content = applicationJOSE
	}
	return token, content, payload, nil
}

// accessTokenHandler handles access token requests
func (c *ThingGateway) accessTokenHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("accessTokenHandler")

	token, content, payload, err := decodeThingEndpointRequest(r.Msg)
	if err != nil {
		w.SetCode(codes.BadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	b, err := c.Thing.Client.accessToken(token, content, payload)
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	w.Write(b)
	DebugLogger.Println("accessTokenHandler: success")
}

// attributesHandler handles a thing attributes requests
func (c *ThingGateway) attributesHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("attributesHandler")
	names := r.Msg.Query()

	token, format, payload, err := decodeThingEndpointRequest(r.Msg)
	if err != nil {
		w.SetCode(codes.BadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	b, err := c.Thing.Client.attributes(token, format, payload, names)
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	w.Write(b)
	DebugLogger.Println("attributesHandler: success")
}

func dtlsServerConfig(cert ...tls.Certificate) *dtls.Config {
	return &dtls.Config{
		Certificates:         cert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientAuth:           dtls.RequireAnyClientCert,
	}
}

// StartCOAPServer starts a COAP server within the Thing Gateway
func (c *ThingGateway) StartCOAPServer(address string, key crypto.Signer) error {
	if c.coapServer != nil {
		return ErrCOAPServerAlreadyStarted
	}
	if key == nil {
		return errMissingSigner
	}
	c.coapChan = make(chan error, 1)
	mux := coap.NewServeMux()
	mux.HandleFunc("/authenticate", c.authenticateHandler)
	mux.HandleFunc("/aminfo", c.amInfoHandler)
	mux.HandleFunc("/accesstoken", c.accessTokenHandler)
	mux.HandleFunc("/attributes", c.attributesHandler)

	cert, err := publicKeyCertificate(key)
	if err != nil {
		return err
	}
	l, err := net.NewDTLSListener("udp", address, dtlsServerConfig(cert), heartBeat)
	if err != nil {
		return err
	}
	c.address = l.Addr()

	// it is safer to wait for the CoAP server to fully start before returning from the function
	// since instructing the server to shutdown while it is still starting up can cause a hang
	started := make(chan struct{})

	c.coapServer = &coap.Server{
		Listener: l,
		Handler:  mux,
		NotifyStartedFunc: func() {
			close(started)
		},
	}
	go func() {
		c.coapChan <- c.coapServer.ActivateAndServe()
		l.Close()
		c.coapServer = nil
	}()
	<-started
	return nil
}

// ShutdownCOAPServer gracefully shuts the COAP server down
func (c *ThingGateway) ShutdownCOAPServer() {
	if c.coapServer == nil {
		return
	}
	c.coapServer.Shutdown()
	// wait for shutdown to complete
	<-c.coapChan
	c.address = nil
}

// Address returns in string form the address that it is listening on.
func (c *ThingGateway) Address() string {
	if c.address == nil {
		return ""
	}
	return c.address.String()
}
