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

package message

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
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

// CallbackHandler is an interface for an AM callback handler
type CallbackHandler interface {
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
func ProcessCallbacks(callbacks []Callback, handlers []CallbackHandler) error {
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

// NameCallbackHandler handles an AM Username Collector callback
type NameCallbackHandler struct {
	// Name\Username\ID for the identity
	Name string
}

func (h NameCallbackHandler) Match(c Callback) bool {
	return c.Type == TypeNameCallback
}
func (h NameCallbackHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value = h.Name
	return nil
}

// PasswordCallbackHandler handles an AM Password Collector callback
type PasswordCallbackHandler struct {
	// Password for the identity
	Password string
}

func (h PasswordCallbackHandler) Match(c Callback) bool {
	return c.Type == TypePasswordCallback
}
func (h PasswordCallbackHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value = h.Password
	return nil
}

// AttributeCallbackHandler handles an AM attribute collector callback
type AttributeCallbackHandler struct {
	// Attributes is a key-value map containing Thing attributes. Keys should match those requested by AM
	Attributes map[string]string
}

func (h AttributeCallbackHandler) Match(c Callback) bool {
	if c.Type != TypeTextInputCallback || len(c.Output) == 0 {
		return false
	}
	_, ok := h.Attributes[c.Output[0].Value]
	return ok
}
func (h AttributeCallbackHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value, _ = h.Attributes[c.Output[0].Value]
	return nil
}

// X509CertCallbackHandler handles an AM Certificate Collector callback
type X509CertCallbackHandler struct {
	// Certificate
	Cert []byte
}

func (h X509CertCallbackHandler) Match(c Callback) bool {
	return c.Type == TypeTextInputCallback &&
		len(c.Output) > 0 && c.Output[0].Value == PromptX509CertCallback
}
func (h X509CertCallbackHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	c.Input[0].Value = string(h.Cert)
	return nil
}

// PoPCallbackHandler handles an AM private key proof of possession challenge
type PoPCallbackHandler struct {
	// Hash function used to hash the challenge
	Hash crypto.Hash
	// Signer function used to sign the challenge
	Signer crypto.Signer
}

func (h PoPCallbackHandler) Match(c Callback) bool {
	return c.Type == TypeTextInputCallback &&
		len(c.Output) > 0 && c.Output[0].Value == PromptProofOfPossessionCallback
}
func (h PoPCallbackHandler) Respond(c Callback) error {
	if len(c.Input) == 0 {
		return ErrNoInput
	}
	if len(c.Output) < 2 {
		return ErrNoOutput
	}
	challenge := []byte(c.Output[1].Value)

	// hash challenge if hash function is available
	if h.Hash.Available() {
		h1 := h.Hash.New()
		h1.Write(challenge)
		challenge = h1.Sum(nil)
	}
	// sign challenge
	signedChallenge, err := h.Signer.Sign(rand.Reader, challenge, crypto.SHA256)
	if err != nil {
		return err
	}
	// base64 encode
	c.Input[0].Value = base64.StdEncoding.EncodeToString(signedChallenge)
	return nil
}
