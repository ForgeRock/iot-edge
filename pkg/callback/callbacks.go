/*
 * Copyright 2020-2022 ForgeRock AS
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

package callback

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	errNoInput  = errors.New("no input Entry to put response")
	errNoOutput = errors.New("no output Entry for response")
)

const (
	// Authentication callback names
	TypeNameCallback        = "NameCallback"
	TypePasswordCallback    = "PasswordCallback"
	TypeTextInputCallback   = "TextInputCallback"
	TypeHiddenValueCallback = "HiddenValueCallback"
	// Entry keys
	keyHiddenID = "id"
	keyValue    = "value"
	// Thing types used with registration callback
	TypeDevice  ThingType = "device"
	TypeService ThingType = "service"
	TypeGateway ThingType = "gateway"
)

// ThingType describes the type of thing and is stored with the digital identity during registration.
type ThingType string

// Entry represents an Input or Output Entry in a Callback.
type Entry struct {
	Name  string      `json:"name"`
	Value interface{} `json:"value"`
}

func (e Entry) String() string {
	return fmt.Sprintf("{Name:%v Value:%v}", e.Name, e.Value)
}

// Callback describes an AM callback request and response structure.
type Callback struct {
	Type   string  `json:"type,omitempty"`
	Output []Entry `json:"output,omitempty"`
	Input  []Entry `json:"input,omitempty"`
}

func (c Callback) String() string {
	return fmt.Sprintf("{Callback Type:%v Output:%v Input:%v}", c.Type, c.Output, c.Input)
}

// ID will verify that the callback is a HiddenValueCallback and return the ID value if one exists.
func (c Callback) ID() string {
	if c.Type != TypeHiddenValueCallback {
		return ""
	}
	for _, e := range c.Output {
		if e.Name == keyHiddenID {
			id, ok := e.Value.(string)
			if !ok {
				debug.Logger.Printf("Expected 'string' id %v", e)
			}
			return id
		}
	}
	return ""
}

// Handler is an interface for an AM callback handler.
type Handler interface {
	// Handle the callback by modifying it. Return true if the callback was handled.
	Handle(cb Callback) (bool, error)
}

// NameHandler handles an AM Username Collector callback.
type NameHandler struct {
	// Name\Username\ID for the identity
	Name string
}

func (h NameHandler) Handle(cb Callback) (bool, error) {
	if cb.Type != TypeNameCallback {
		return false, nil
	}
	if len(cb.Input) == 0 {
		return true, errNoInput
	}
	cb.Input[0].Value = h.Name
	return true, nil
}

// PasswordHandler handles an AM Password Collector callback.
type PasswordHandler struct {
	// Password for the identity
	Password string
}

func (h PasswordHandler) Handle(cb Callback) (bool, error) {
	if cb.Type != TypePasswordCallback {
		return false, nil
	}
	if len(cb.Input) == 0 {
		return true, errNoInput
	}
	cb.Input[0].Value = h.Password
	return true, nil
}

// AuthenticateHandler handles the callback received from the Authenticate Thing tree node.
type AuthenticateHandler struct {
	Audience string
	ThingID  string
	KeyID    string
	Key      crypto.Signer
	Claims   func() interface{}
}

type jwtVerifyClaims struct {
	Sub       string    `json:"sub"`
	Iss       string    `json:"iss,omitempty"`
	Aud       string    `json:"aud"`
	ThingType ThingType `json:"thingType,omitempty"`
	Iat       int64     `json:"iat"`
	Exp       int64     `json:"exp"`
	Nonce     string    `json:"nonce,omitempty"`
	CNF       struct {
		KID string           `json:"kid,omitempty"`
		JWK *jose.JSONWebKey `json:"jwk,omitempty"`
	} `json:"cnf"`
}

func (c jwtVerifyClaims) String() string {
	return fmt.Sprintf("{sub:%s, aud:%s, ThingType:%s}", c.Sub, c.Aud, c.ThingType)
}

func baseJWTClaims(thingID, audience string) jwtVerifyClaims {
	return jwtVerifyClaims{
		Sub: thingID,
		Aud: audience,
		Iat: time.Now().Unix(),
		Exp: time.Now().Add(5 * time.Minute).Unix(),
	}
}

func (h AuthenticateHandler) Handle(cb Callback) (bool, error) {
	jwtPoPAuth := cb.ID() == "jwt-pop-authentication"
	clientAssertion := cb.ID() == "client_assertion"
	if !jwtPoPAuth && !clientAssertion {
		return false, nil
	}
	if len(cb.Input) == 0 {
		return true, errNoInput
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader(jose.HeaderType, "JWT")
	claims := baseJWTClaims(h.ThingID, h.Audience)
	if jwtPoPAuth {
		var challenge string
		for _, e := range cb.Output {
			if e.Name == keyValue {
				var ok bool
				challenge, ok = e.Value.(string)
				if !ok {
					return true, fmt.Errorf("expected `string` challenge %v", e.Value)
				}
				break
			}
		}
		if challenge == "" {
			return true, errNoOutput
		}
		claims.Nonce = challenge
		claims.CNF.KID = h.KeyID
	} else {
		opts.WithHeader("kid", h.KeyID)
		claims.Iss = h.ThingID
	}

	sig, err := jws.NewSigner(h.Key, opts)
	if err != nil {
		return true, err
	}
	builder := jwt.Signed(sig).Claims(claims)
	if h.Claims != nil {
		builder = builder.Claims(h.Claims())
	}
	response, err := builder.CompactSerialize()
	if err != nil {
		return true, err
	}

	cb.Input[0].Value = response
	return true, nil
}

// RegisterHandler handles the callback received from the Register Thing tree node.
type RegisterHandler struct {
	Audience     string
	ThingID      string
	ThingType    ThingType
	KeyID        string
	Key          crypto.Signer
	Certificates []*x509.Certificate
	Claims       func() interface{}
}

func (h RegisterHandler) Handle(cb Callback) (bool, error) {
	if cb.ID() != "jwt-pop-registration" {
		return false, nil
	}
	if len(cb.Input) == 0 {
		return true, errNoInput
	}
	var challenge string
	for _, e := range cb.Output {
		if e.Name == keyValue {
			var ok bool
			challenge, ok = e.Value.(string)
			if !ok {
				return true, fmt.Errorf("expected `string` challenge %v", e.Value)
			}
			break
		}
	}
	if challenge == "" {
		return true, errNoOutput
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")

	sig, err := jws.NewSigner(h.Key, opts)
	if err != nil {
		return true, err
	}
	claims := baseJWTClaims(h.ThingID, h.Audience)
	claims.Nonce = challenge
	claims.ThingType = h.ThingType
	claims.CNF.JWK = &jose.JSONWebKey{
		Key:          h.Key.Public(),
		Certificates: h.Certificates,
		KeyID:        h.KeyID,
		Use:          "sig",
	}
	builder := jwt.Signed(sig).Claims(claims)
	if h.Claims != nil {
		builder = builder.Claims(h.Claims())
	}
	response, err := builder.CompactSerialize()
	if err != nil {
		return true, err
	}

	cb.Input[0].Value = response
	return true, nil
}
