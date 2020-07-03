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

package callback

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/jws"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

var (
	ErrNoInput    = errors.New("no input Entry to put response")
	ErrNoOutput   = errors.New("no output Entry for response")
	ErrNotHandled = errors.New("callback not handled")
)

const (
	TypeNameCallback      = "NameCallback"
	TypePasswordCallback  = "PasswordCallback"
	TypeTextInputCallback = "TextInputCallback"
)

// Entry represents an Input or Output Entry in a Callback
type Entry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func (e Entry) String() string {
	return fmt.Sprintf("{Name:%v Value:%v}", e.Name, e.Value)
}

// Callback describes an AM callback request and response structure
type Callback struct {
	Type   string  `json:"type,omitempty"`
	Output []Entry `json:"output,omitempty"`
	Input  []Entry `json:"input,omitempty"`
}

func (c Callback) String() string {
	return fmt.Sprintf("{Callback Type:%v Output:%v Input:%v}", c.Type, c.Output, c.Input)
}

// ID returns the ID value of the callback if one exists
func (c Callback) ID() string {
	if c.Type != "HiddenValueCallback" {
		return ""
	}
	for _, e := range c.Output {
		if e.Name == "id" {
			return e.Value
		}
	}
	return ""
}

// CallbackHandler is an interface for an AM callback handler
type Handler interface {
	// Handle the callback by modifying it
	Handle(cb Callback) error
}

// ProofOfPossessionHandler responds to an AM proof of possession callback
type ProofOfPossessionHandler interface {
	Handler
	SigningKey() crypto.Signer
}

// NameHandler handles an AM Username Collector callback
type NameHandler struct {
	// Name\Username\ID for the identity
	Name string
}

func (h NameHandler) Handle(cb Callback) error {
	if cb.Type != TypeNameCallback {
		return ErrNotHandled
	}
	if len(cb.Input) == 0 {
		return ErrNoInput
	}
	cb.Input[0].Value = h.Name
	return nil
}

// PasswordHandler handles an AM Password Collector callback
type PasswordHandler struct {
	// Password for the identity
	Password string
}

func (h PasswordHandler) Handle(cb Callback) error {
	if cb.Type != TypePasswordCallback {
		return ErrNotHandled
	}
	if len(cb.Input) == 0 {
		return ErrNoInput
	}
	cb.Input[0].Value = h.Password
	return nil
}

type AuthenticateHandler struct {
	Realm   string
	ThingID string
	KeyID   string
	Key     crypto.Signer
	Claims  func() interface{}
}

func (h AuthenticateHandler) SigningKey() crypto.Signer {
	return h.Key
}

type jwtVerifyClaims struct {
	Sub       string    `json:"sub"`
	Aud       string    `json:"aud"`
	ThingType ThingType `json:"thingType"`
	Iat       int64     `json:"iat"`
	Exp       int64     `json:"exp"`
	Nonce     string    `json:"nonce"`
	CNF       struct {
		KID string           `json:"kid,omitempty"`
		JWK *jose.JSONWebKey `json:"jwk,omitempty"`
	} `json:"cnf"`
}

func (c jwtVerifyClaims) String() string {
	return fmt.Sprintf("{sub:%s, aud:%s, ThingType:%s}", c.Sub, c.Aud, c.ThingType)
}

func baseJWTClaims(thingID, realm, challenge string) jwtVerifyClaims {
	return jwtVerifyClaims{
		Sub:   thingID,
		Aud:   realm,
		Iat:   time.Now().Unix(),
		Exp:   time.Now().Add(5 * time.Minute).Unix(),
		Nonce: challenge,
	}
}

func (h AuthenticateHandler) Handle(cb Callback) error {
	if cb.ID() != "jwt-pop-authentication" {
		return ErrNotHandled
	}
	if len(cb.Input) == 0 {
		return ErrNoInput
	}
	var challenge string
	for _, e := range cb.Output {
		if e.Name == "value" {
			challenge = e.Value
			break
		}
	}
	if challenge == "" {
		return ErrNoOutput
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")

	sig, err := jws.NewSigner(h.Key, opts)
	if err != nil {
		return err
	}
	claims := baseJWTClaims(h.ThingID, h.Realm, challenge)
	claims.CNF.KID = h.KeyID
	builder := jwt.Signed(sig).Claims(claims)
	if h.Claims != nil {
		builder = builder.Claims(h.Claims())
	}
	response, err := builder.CompactSerialize()
	if err != nil {
		return err
	}

	cb.Input[0].Value = response
	return nil
}

type RegisterHandler struct {
	Realm        string
	ThingID      string
	ThingType    ThingType
	KeyID        string
	Key          crypto.Signer
	Certificates []*x509.Certificate
	Claims       func() interface{}
}

func (h RegisterHandler) SigningKey() crypto.Signer {
	return h.Key
}

func (h RegisterHandler) Handle(cb Callback) error {
	if cb.ID() != "jwt-pop-registration" {
		return ErrNotHandled
	}
	if len(cb.Input) == 0 {
		return ErrNoInput
	}
	var challenge string
	for _, e := range cb.Output {
		if e.Name == "value" {
			challenge = e.Value
			break
		}
	}
	if challenge == "" {
		return ErrNoOutput
	}

	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")

	// check that the signer is supported
	alg, err := jws.JWAFromKey(h.Key)
	if err != nil {
		return err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(h.Key)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return err
	}
	claims := baseJWTClaims(h.ThingID, h.Realm, challenge)
	claims.ThingType = h.ThingType
	claims.CNF.JWK = &jose.JSONWebKey{
		Key:          h.Key.Public(),
		Certificates: h.Certificates,
		KeyID:        h.KeyID,
		Algorithm:    string(alg),
		Use:          "sig",
	}
	builder := jwt.Signed(sig).Claims(claims)
	if h.Claims != nil {
		builder = builder.Claims(h.Claims())
	}
	response, err := builder.CompactSerialize()
	if err != nil {
		return err
	}

	cb.Input[0].Value = response
	return nil
}

// ThingType describes the Thing type
type ThingType string

const (
	TypeDevice  ThingType = "device"
	TypeService ThingType = "service"
	TypeGateway ThingType = "gateway"
)