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
	"errors"
	"fmt"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"time"
)

var (
	ErrNoInput  = errors.New("no input Entry to put response")
	ErrNoOutput = errors.New("no output Entry for response")
)

const (
	TypeNameCallback      = "NameCallback"
	TypePasswordCallback  = "PasswordCallback"
	TypeTextInputCallback = "TextInputCallback"

	PromptX509CertCallback          = "PEM encoded X.509 Certificate"
	PromptProofOfPossessionCallback = "challenge"
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
	// Match returns true if the handler should respond to the callback
	Match(Callback) bool
	// Respond by modifying the callback
	Respond(Callback) error
}

// ErrMissingHandler is returned when the callback cannot be handled
type ErrMissingHandler struct {
	callback Callback
}

func (e ErrMissingHandler) Error() string {
	return fmt.Sprintf("can not respond to %v", e.callback)
}

// ProcessCallbacks attempts to respond to the callbacks with the given callback handlers
func ProcessCallbacks(callbacks []Callback, handlers []Handler) error {
	for _, cb := range callbacks {
		matched := false
	handlerLoop:
		for _, h := range handlers {
			if matched = h.Match(cb); matched {
				err := h.Respond(cb)
				if err != nil {
					return err
				}
				break handlerLoop
			}
		}
		if !matched {
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

func (h NameHandler) Match(c Callback) bool {
	return c.Type == TypeNameCallback
}
func (h NameHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value = h.Name
	return nil
}

// PasswordHandler handles an AM Password Collector callback
type PasswordHandler struct {
	// Password for the identity
	Password string
}

func (h PasswordHandler) Match(c Callback) bool {
	return c.Type == TypePasswordCallback
}
func (h PasswordHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value = h.Password
	return nil
}

// AttributeHandler handles an AM attribute collector callback
type AttributeHandler struct {
	// Attributes is a key-value map containing Thing attributes. Keys should match those requested by AM
	Attributes map[string]string
}

func (h AttributeHandler) Match(c Callback) bool {
	if c.Type != TypeTextInputCallback || len(c.Output) == 0 {
		return false
	}
	_, ok := h.Attributes[c.Output[0].Value]
	return ok
}
func (h AttributeHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value, _ = h.Attributes[c.Output[0].Value]
	return nil
}

type JWTPoPAuthHandler struct {
	KID             string
	ConfirmationKey crypto.Signer
	ThingID         string
	ThingType       string
	Realm           string
}

func (h JWTPoPAuthHandler) Match(c Callback) bool {
	return c.ID() == "jwt-pop-authentication"
}

func (h JWTPoPAuthHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	var challenge string
	for _, e := range c.Output {
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
	alg, err := signingJWAFromKey(h.ConfirmationKey)
	if err != nil {
		return err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(h.ConfirmationKey)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return err
	}
	claims := jwtVerifyClaims{}
	claims.Sub = h.ThingID
	claims.Aud = h.Realm
	claims.ThingType = h.ThingType
	claims.Nonce = challenge
	claims.CNF.KID = h.KID
	claims.Iat = time.Now().Unix()
	claims.Exp = time.Now().Add(5 * time.Minute).Unix()
	builder := jwt.Signed(sig).Claims(claims)
	response, err := builder.CompactSerialize()
	c.Input[0].Value = response
	return err
}
