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
	"crypto/x509"
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

var (
	ErrNoInput    = errors.New("no input Entry to put response")
	ErrNoOutput   = errors.New("no output Entry for response")
	errNotHandled = errors.New("callback not handled")
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
	// Type returns the Thing type
	Type() ThingType
	// ConfirmationKey returns the Thing's confirmation key
	ConfirmationKey() SigningKey
}

// CallbackHandler is an interface for an AM callback handler
type Handler interface {
	// Handle the callback by modifying it
	Handle(id ThingIdentity, cb Callback) error
}

// ErrMissingHandler is returned when the callback cannot be handled
type ErrMissingHandler struct {
	callback Callback
}

func (e ErrMissingHandler) Error() string {
	return fmt.Sprintf("can not respond to %v", e.callback)
}

// ProcessCallbacks attempts to respond to the callbacks with the given callback handlers
func ProcessCallbacks(id ThingIdentity, handlers []Handler, callbacks []Callback) (err error) {
	for _, cb := range callbacks {
	handlerLoop:
		for _, h := range handlers {
			switch err = h.Handle(id, cb); err {
			case errNotHandled:
				continue
			case nil:
				break handlerLoop
			default:
				DebugLogger.Println(err)
				continue
			}
		}
		if err != nil {
			return ErrMissingHandler{callback: cb}
		}
	}
	return nil
}

// NameHandler handles an AM Username Collector callback
type NameHandler struct {
	// Name\Username\ID for the identity
	Name string
}

func (h NameHandler) Handle(id ThingIdentity, cb Callback) error {
	if cb.Type != TypeNameCallback {
		return errNotHandled
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

func (h PasswordHandler) Handle(id ThingIdentity, cb Callback) error {
	if cb.Type != TypePasswordCallback {
		return errNotHandled
	}
	if len(cb.Input) == 0 {
		return ErrNoInput
	}
	cb.Input[0].Value = h.Password
	return nil
}

type ThingJWTHandler struct {
	ThingID      string
	Certificates []*x509.Certificate
}

func (h ThingJWTHandler) Handle(id ThingIdentity, cb Callback) error {
	var registration bool
	switch cb.ID() {
	case "jwt-pop-authentication":
		registration = false
	case "jwt-pop-registration":
		registration = true
	default:
		return errNotHandled
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

	key := id.ConfirmationKey()

	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")

	// check that the signer is supported
	alg, err := signingJWAFromKey(key.Signer)
	if err != nil {
		return err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(key.Signer)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return err
	}
	claims := jwtVerifyClaims{}
	claims.Sub = h.ThingID
	claims.Aud = id.Realm()
	claims.ThingType = id.Type()
	claims.Nonce = challenge
	if registration {
		claims.CNF.JWK = &jose.JSONWebKey{
			Key:          key.Signer.Public(),
			Certificates: h.Certificates,
			KeyID:        key.KID,
			Algorithm:    string(alg),
			Use:          "sig",
		}
	} else {
		claims.CNF.KID = key.KID
	}
	claims.Iat = time.Now().Unix()
	claims.Exp = time.Now().Add(5 * time.Minute).Unix()
	builder := jwt.Signed(sig).Claims(claims)
	response, err := builder.CompactSerialize()
	cb.Input[0].Value = response
	return err
}
