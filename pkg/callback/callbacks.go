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
	"encoding/base64"
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

// ThingIdentity allows a callback handler to request information from the Thing
// This is especially important for dynamic data
type ThingIdentity interface {
	// Realm returns the realm that the identity belongs
	Realm() string
}

// CallbackHandler is an interface for an AM callback handler
type Handler interface {
	// Handle the callback by modifying it
	Handle(id ThingIdentity, cb Callback, metadata *AuthMetadata) error
}

type AuthMetadata struct {
	ConfirmationKey crypto.Signer
}

// NameHandler handles an AM Username Collector callback
type NameHandler struct {
	// Name\Username\ID for the identity
	Name string
}

func (h NameHandler) Handle(id ThingIdentity, cb Callback, metadata *AuthMetadata) error {
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

func (h PasswordHandler) Handle(id ThingIdentity, cb Callback, metadata *AuthMetadata) error {
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
	ThingID           string
	ConfirmationKeyID string
	// Restrictions: confirmationKey uses ECDSA with a P-256, P-384 or P-512 curve. Sign returns the signature ans1 encoded.
	ConfirmationKey crypto.Signer
	Claims          func() interface{}
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

func (h AuthenticateHandler) Handle(id ThingIdentity, cb Callback, metadata *AuthMetadata) error {
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

	sig, err := jws.NewSigner(h.ConfirmationKey, opts)
	if err != nil {
		return err
	}
	claims := baseJWTClaims(h.ThingID, id.Realm(), challenge)
	claims.CNF.KID = h.ConfirmationKeyID
	builder := jwt.Signed(sig).Claims(claims)
	if h.Claims != nil {
		builder = builder.Claims(h.Claims())
	}
	response, err := builder.CompactSerialize()
	if err != nil {
		return err
	}

	cb.Input[0].Value = response
	metadata.ConfirmationKey = h.ConfirmationKey
	return nil
}

type RegisterHandler struct {
	ThingID           string
	ThingType         ThingType
	ConfirmationKeyID string
	// Restrictions: confirmationKey uses ECDSA with a P-256, P-384 or P-512 curve. Sign returns the signature ans1 encoded.
	ConfirmationKey crypto.Signer
	Certificates    []*x509.Certificate
	Claims          func() interface{}
}

// createKID creates a key ID for a signer
func createKID(key crypto.Signer) (string, error) {
	thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(thumbprint), nil
}

func (h RegisterHandler) Handle(id ThingIdentity, cb Callback, metadata *AuthMetadata) error {
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
	alg, err := jws.JWAFromKey(h.ConfirmationKey)
	if err != nil {
		return err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(h.ConfirmationKey)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return err
	}
	claims := baseJWTClaims(h.ThingID, id.Realm(), challenge)
	claims.ThingType = h.ThingType
	claims.CNF.JWK = &jose.JSONWebKey{
		Key:          h.ConfirmationKey.Public(),
		Certificates: h.Certificates,
		KeyID:        h.ConfirmationKeyID,
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
	metadata.ConfirmationKey = h.ConfirmationKey
	return nil
}

// ThingType describes the Thing type
type ThingType string

const (
	TypeDevice  ThingType = "device"
	TypeService ThingType = "service"
	TypeGateway ThingType = "gateway"
)
