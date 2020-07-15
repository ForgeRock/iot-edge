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

package thing

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/jws"
	"github.com/ForgeRock/iot-edge/internal/tokencache"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	coapnet "github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
	"math/big"
	"net"
	"time"
)

// CoAP server design
// CoAP method is taken from the HTTP method used to communicate with AM
// The CoAP response status codes follow the CoAP-HTTP proxy guidance in the CoAP specification
// https://tools.ietf.org/html/rfc7252#section-10.1

// ErrCOAPServerAlreadyStarted indicates that a CoAP server has already been started by the Thing Gateway
var ErrCOAPServerAlreadyStarted = errors.New("CoAP server has already been started")

// ThingGateway represents the Thing Gateway
type ThingGateway struct {
	Thing     defaultThing
	authCache *tokencache.Cache
	// coap server
	coapServer *coap.Server
	coapChan   chan error
	address    net.Addr
}

// NewThingGateway creates a new Thing Gateway
func NewThingGateway(baseURL string, realm string, authTree string, handlers []callback.Handler) *ThingGateway {
	return &ThingGateway{
		Thing: defaultThing{
			connection: &amConnection{baseURL: baseURL, realm: realm, authTree: authTree},
			handlers:   handlers,
		},
		authCache: tokencache.New(5*time.Minute, 10*time.Minute),
	}
}

// Initialise the Thing Gateway
func (c *ThingGateway) Initialise() error {
	err := c.Thing.connection.initialise()
	if err != nil {
		return err
	}
	return c.Thing.authenticate()
}

// AuthenticateWith the given authentication tree
func (c *ThingGateway) AuthenticateWith(tree string) *ThingGateway {
	c.Thing.connection.(*amConnection).authTree = tree
	return c
}

// authenticate a Thing with AM using the given payload
func (c *ThingGateway) authenticate(auth authenticatePayload) (reply authenticatePayload, err error) {
	if auth.AuthIDKey != "" {
		auth.AuthId, _ = c.authCache.Get(auth.AuthIDKey)
	}
	auth.AuthIDKey = ""

	reply, err = c.Thing.connection.authenticate(auth)
	if err != nil {
		return
	}

	// if reply has a token, authentication has successfully completed
	if reply.HasSessionToken() {
		return reply, nil
	}

	if reply.AuthId == "" {
		return reply, fmt.Errorf("no Auth Id in reply")
	}

	// Auth ID as it is usually too big for a single UDP message.
	// Instead, create a shorter key and cache the Auth Id, returning the key to the caller.
	// Use the hash value of the id as its key
	d := sha256.Sum256([]byte(reply.AuthId))
	reply.AuthIDKey = base64.StdEncoding.EncodeToString(d[:])
	c.authCache.Add(reply.AuthIDKey, reply.AuthId)
	reply.AuthId = ""

	return
}

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
	info, err := c.Thing.connection.amInfo()
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
		if err := jws.ExtractClaims(payload, &claims); err != nil {
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

	b, err := c.Thing.connection.accessToken(token, content, payload)
	if err != nil {
		if errors.Is(err, ErrUnauthorised) {
			w.SetCode(codes.Unauthorized)
		} else {
			w.SetCode(codes.GatewayTimeout)
		}
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
	b, err := c.Thing.connection.attributes(token, format, payload, names)
	if err != nil {
		if errors.Is(err, ErrUnauthorised) {
			w.SetCode(codes.Unauthorized)
		} else {
			w.SetCode(codes.GatewayTimeout)
		}
		w.Write([]byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	w.Write(b)
	DebugLogger.Println("attributesHandler: success")
}

// sessionHandler handles a session validation request
func (c *ThingGateway) sessionHandler(w coap.ResponseWriter, r *coap.Request) {
	DebugLogger.Println("sessionHandler")

	var token sessionToken
	if err := json.Unmarshal(r.Msg.Payload(), &token); err != nil {
		w.SetCode(codes.BadRequest)
		w.Write([]byte(err.Error()))
		return
	}
	switch r.Msg.QueryString() {
	case "_action=validate":
		valid, err := c.Thing.connection.validateSession(token.TokenID)
		if err != nil {
			w.SetCode(codes.GatewayTimeout)
			w.Write([]byte(err.Error()))
			return
		}
		if valid {
			w.SetCode(codes.Changed)
		} else {
			w.SetCode(codes.Unauthorized)
		}
		w.Write(nil)
		DebugLogger.Printf("sessionHandler: success. validate %v", valid)
	case "_action=logout":
		err := c.Thing.connection.logoutSession(token.TokenID)
		if err != nil {
			w.SetCode(codes.GatewayTimeout)
			w.Write([]byte(err.Error()))
			return
		}
		w.SetCode(codes.Changed)
		w.Write(nil)
		DebugLogger.Printf("sessionHandler: success. log out")
	default:
		w.SetCode(codes.BadRequest)
		w.Write([]byte("unknown/missing query"))
		return
	}
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
		return jws.ErrMissingSigner
	}
	c.coapChan = make(chan error, 1)
	mux := coap.NewServeMux()
	mux.HandleFunc("/authenticate", c.authenticateHandler)
	mux.HandleFunc("/aminfo", c.amInfoHandler)
	mux.HandleFunc("/accesstoken", c.accessTokenHandler)
	mux.HandleFunc("/attributes", c.attributesHandler)
	mux.HandleFunc("/session", c.sessionHandler)

	cert, err := publicKeyCertificate(key)
	if err != nil {
		return err
	}
	l, err := coapnet.NewDTLSListener("udp", address, dtlsServerConfig(cert), heartBeat)
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

// publicKeyCertificate returns a stripped down tls certificate containing the public key
func publicKeyCertificate(key crypto.Signer) (cert tls.Certificate, err error) {
	if key == nil {
		return cert, jws.ErrMissingSigner
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	raw, err := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if err != nil {
		return cert, err
	}
	return tls.Certificate{

		Certificate: [][]byte{raw},
		PrivateKey:  key,
		Leaf:        &template,
	}, nil
}
