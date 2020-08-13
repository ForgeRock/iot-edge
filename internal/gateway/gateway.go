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
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	ithing "github.com/ForgeRock/iot-edge/v7/internal/thing"
	"github.com/ForgeRock/iot-edge/v7/internal/tokencache"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/go-ocf/go-coap"
	"github.com/go-ocf/go-coap/codes"
	coapnet "github.com/go-ocf/go-coap/net"
	"github.com/pion/dtls/v2"
)

// CoAP server design
// CoAP method is taken from the HTTP method used to communicate with AM
// The CoAP response status codes follow the CoAP-HTTP proxy guidance in the CoAP specification
// https://tools.ietf.org/html/rfc7252#section-10.1

// ErrCOAPServerAlreadyStarted indicates that a CoAP server has already been started by the Thing Gateway
var ErrCOAPServerAlreadyStarted = errors.New("CoAP server has already been started")

// ThingGateway represents the Thing Gateway
type ThingGateway struct {
	gatewayThing     thing.Thing
	authCache        *tokencache.Cache
	callbackHandlers []callback.Handler
	// coap server
	coapServer *coap.Server
	coapChan   chan error
	address    net.Addr
	// AM connection
	amConnection client.Connection
	amURL        string
	realm        string
	authTree     string
	timeout      time.Duration
}

// NewThingGateway creates a new Thing Gateway
func NewThingGateway(baseURL string, realm string, authTree string, timeout time.Duration, handlers []callback.Handler) *ThingGateway {
	return &ThingGateway{
		authCache:        tokencache.New(5*time.Minute, 10*time.Minute),
		amURL:            baseURL,
		realm:            realm,
		authTree:         authTree,
		callbackHandlers: handlers,
		timeout:          timeout,
	}
}

// Initialise the Thing Gateway
func (c *ThingGateway) Initialise() error {
	amURL, err := url.Parse(c.amURL)
	if err != nil {
		return err
	}
	// create a connection to AM for forwarding thing requests
	c.amConnection, err = client.NewConnection().
		ConnectTo(amURL).
		InRealm(c.realm).
		WithTree(c.authTree).
		TimeoutRequestAfter(c.timeout).
		Create()
	if err != nil {
		return err
	}
	// create (register/authenticate) a thing representing the gateway
	gatewayBuilder := &ithing.BaseBuilder{}
	c.gatewayThing, err = gatewayBuilder.
		WithConnection(c.amConnection).
		HandleCallbacksWith(c.callbackHandlers...).
		Create()
	return err
}

// SetAuthenticationTree changes the authentication tree that the gateway was created with.
// This is a convenience function for functional testing.
func SetAuthenticationTree(c *ThingGateway, tree string) {
	client.SetAuthenticationTree(c.amConnection, tree)
}

// authenticate a Thing with AM using the given payload
func (c *ThingGateway) authenticate(auth client.AuthenticatePayload) (reply client.AuthenticatePayload, err error) {
	if auth.AuthIDKey != "" {
		auth.AuthId, _ = c.authCache.Get(auth.AuthIDKey)
	}
	auth.AuthIDKey = ""

	reply, err = c.amConnection.Authenticate(auth)
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
	debug.Logger.Println("authenticateHandler")
	var auth client.AuthenticatePayload
	if err := json.Unmarshal(r.Msg.Payload(), &auth); err != nil {
		debug.Logger.Printf("Unable to unmarshall payload; %s", err)
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte("Unable to unmarshal payload"))
		return
	}

	reply, err := c.authenticate(auth)
	if err != nil {
		debug.Logger.Printf("Error connecting to AM; %s", err)
		w.SetCode(codes.Unauthorized)
		writeResponse(w, []byte(err.Error()))
		return
	}

	b, err := json.Marshal(reply)
	if err != nil {
		debug.Logger.Printf("Error marshalling Auth Payload; %s", err)
		w.SetCode(codes.BadGateway)
		writeResponse(w, []byte(err.Error()))
		return
	}
	w.SetCode(codes.Valid)
	writeResponse(w, b)
	debug.Logger.Println("authenticateHandler: success")
}

// amInfoHandler handles AM Info requests
func (c *ThingGateway) amInfoHandler(w coap.ResponseWriter, r *coap.Request) {
	debug.Logger.Println("amInfoHandler")
	info, err := c.amConnection.AMInfo()
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		writeResponse(w, nil)
		return
	}
	b, err := json.Marshal(info)
	if err != nil {
		debug.Logger.Printf("Error marshalling amInfo; %s", err)
		w.SetCode(codes.BadGateway)
		writeResponse(w, []byte(err.Error()))
		return
	}
	w.SetCode(codes.Content)
	writeResponse(w, b)
	debug.Logger.Println("amInfoHandler: success")
}

func decodeThingEndpointRequest(msg coap.Message) (token string, content client.ContentType, payload string, err error) {
	coapFormat, ok := msg.Option(coap.ContentFormat).(coap.MediaType)
	if !ok {
		return token, content, payload, fmt.Errorf("missing content format")
	}

	switch coapFormat {
	case coap.AppJSON:
		var request client.ThingEndpointPayload
		if err := json.Unmarshal(msg.Payload(), &request); err != nil {
			return token, content, payload, err
		}
		token = request.Token
		content = client.ApplicationJSON
		payload = request.Payload
	case client.AppJOSE:
		payload = string(msg.Payload())
		// get SSO token from the CSRF claim in the JWT
		var claims struct {
			CSRF string `json:"csrf"`
		}
		if err := jws.ExtractClaims(payload, &claims); err != nil {
			return token, content, payload, err
		}
		token = claims.CSRF
		content = client.ApplicationJOSE
	}
	return token, content, payload, nil
}

// accessTokenHandler handles access token requests
func (c *ThingGateway) accessTokenHandler(w coap.ResponseWriter, r *coap.Request) {
	debug.Logger.Println("accessTokenHandler")

	token, content, payload, err := decodeThingEndpointRequest(r.Msg)
	if err != nil {
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte(err.Error()))
		return
	}

	b, err := c.amConnection.AccessToken(token, content, payload)
	if err != nil {
		if errors.Is(err, client.ErrUnauthorised) {
			w.SetCode(codes.Unauthorized)
		} else {
			w.SetCode(codes.GatewayTimeout)
		}
		writeResponse(w, []byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	writeResponse(w, b)
	debug.Logger.Println("accessTokenHandler: success")
}

// attributesHandler handles a thing attributes requests
func (c *ThingGateway) attributesHandler(w coap.ResponseWriter, r *coap.Request) {
	debug.Logger.Println("attributesHandler")
	names := r.Msg.Query()

	token, format, payload, err := decodeThingEndpointRequest(r.Msg)
	if err != nil {
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte(err.Error()))
		return
	}
	b, err := c.amConnection.Attributes(token, format, payload, names)
	if err != nil {
		if errors.Is(err, client.ErrUnauthorised) {
			w.SetCode(codes.Unauthorized)
		} else {
			w.SetCode(codes.GatewayTimeout)
		}
		writeResponse(w, []byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	writeResponse(w, b)
	debug.Logger.Println("attributesHandler: success")
}

// sessionHandler handles a session validation request
func (c *ThingGateway) sessionHandler(w coap.ResponseWriter, r *coap.Request) {
	debug.Logger.Println("sessionHandler")

	var token client.SessionToken
	if err := json.Unmarshal(r.Msg.Payload(), &token); err != nil {
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte(err.Error()))
		return
	}
	switch r.Msg.QueryString() {
	case "_action=validate":
		valid, err := c.amConnection.ValidateSession(token.TokenID)
		if err != nil {
			w.SetCode(codes.GatewayTimeout)
			writeResponse(w, []byte(err.Error()))
			return
		}
		if valid {
			w.SetCode(codes.Changed)
		} else {
			w.SetCode(codes.Unauthorized)
		}
		writeResponse(w, nil)
		debug.Logger.Printf("sessionHandler: success. validate %v", valid)
	case "_action=logout":
		err := c.amConnection.LogoutSession(token.TokenID)
		if err != nil {
			w.SetCode(codes.GatewayTimeout)
			writeResponse(w, []byte(err.Error()))
			return
		}
		w.SetCode(codes.Changed)
		writeResponse(w, nil)
		debug.Logger.Printf("sessionHandler: success. log out")
	default:
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte("unknown/missing query"))
		return
	}
}

// introspectHandler handles an introspect OAuth2 access token request
func (c *ThingGateway) introspectHandler(w coap.ResponseWriter, r *coap.Request) {
	debug.Logger.Println("introspectHandler")

	coapFormat, ok := r.Msg.Option(coap.ContentFormat).(coap.MediaType)
	if !ok || coapFormat != coap.AppJSON {
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte("missing/incorrect content format"))
		return
	}

	var request client.IntrospectPayload
	err := json.Unmarshal(r.Msg.Payload(), &request)
	if err != nil {
		w.SetCode(codes.BadRequest)
		writeResponse(w, []byte(err.Error()))
		return
	}

	introspection, err := c.amConnection.IntrospectAccessToken(request.Token)
	if err != nil {
		w.SetCode(codes.GatewayTimeout)
		writeResponse(w, []byte(err.Error()))
		return
	}
	w.SetCode(codes.Changed)
	writeResponse(w, introspection)
	debug.Logger.Println("introspectHandler: success")
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
	mux.HandleFunc("/introspect", c.introspectHandler)
	mux.HandleFunc("/attributes", c.attributesHandler)
	mux.HandleFunc("/session", c.sessionHandler)

	cert, err := frcrypto.PublicKeyCertificate(key)
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
	if err := c.coapServer.Shutdown(); err != nil {
		debug.Logger.Println(err)
		return
	}
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

func writeResponse(w coap.ResponseWriter, response []byte) {
	if _, err := w.Write(response); err != nil {
		debug.Logger.Println(err)
	}
}
