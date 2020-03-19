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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
)

func dummyCB(callbackType string, prompts ...string) Callback {
	l := len(prompts)
	if l == 0 {
		l = 1
	}
	cb := Callback{
		Type:   callbackType,
		Output: make([]entry, l),
		Input:  make([]entry, l),
	}
	for i, p := range prompts {
		cb.Output[i].Value = p
	}
	return cb
}

func TestCallbackHandler_Match(t *testing.T) {
	attributes := make(map[string]string)
	attributes["thingMode"] = "test"

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		cb      Callback
		handler CallbackHandler
		want    bool
	}{
		// NameCallbackHandler
		{name: "Name/True", cb: dummyCB(TypeNameCallback), handler: NameCallbackHandler{Name: "Odysseus"}, want: true},
		{name: "Name/False", cb: dummyCB(TypeTextInputCallback), handler: NameCallbackHandler{Name: "Odysseus"}, want: false},
		// PasswordCallbackHandler
		{name: "Password/True", cb: dummyCB(TypePasswordCallback), handler: PasswordCallbackHandler{Password: "password"}, want: true},
		{name: "Password/False", cb: dummyCB(TypeTextInputCallback), handler: PasswordCallbackHandler{Password: "password"}, want: false},
		// AttributeCallbackHandler
		{name: "Attribute/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: AttributeCallbackHandler{Attributes: attributes}, want: false},
		{name: "Attribute/False/WrongType", cb: dummyCB(TypeNameCallback), handler: AttributeCallbackHandler{Attributes: attributes}, want: false},
		{name: "Attribute/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: AttributeCallbackHandler{Attributes: attributes}, want: false},
		{name: "Attribute/True", cb: dummyCB(TypeTextInputCallback, "thingMode"), handler: AttributeCallbackHandler{Attributes: attributes}, want: true},
		// X509CertCallbackHandler
		{name: "X509Cert/False/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: X509CertCallbackHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/False/WrongType", cb: dummyCB(TypeNameCallback, PromptX509CertCallback), handler: X509CertCallbackHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: X509CertCallbackHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/True", cb: dummyCB(TypeTextInputCallback, PromptX509CertCallback), handler: X509CertCallbackHandler{Cert: []byte("12345")}, want: true},
		// ProofOfPossessionCallbackHandler
		{name: "ProofOfPossession/False/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: PoPCallbackHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/False/WrongType", cb: dummyCB(TypeNameCallback, PromptProofOfPossessionCallback), handler: PoPCallbackHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: PoPCallbackHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/True", cb: dummyCB(TypeTextInputCallback, PromptProofOfPossessionCallback), handler: PoPCallbackHandler{Hash: crypto.SHA256, Signer: key}, want: true},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if got := subtest.handler.Match(subtest.cb); got != subtest.want {
				t.Errorf("Match() = %v, want %v", got, subtest.want)
			}
		})
	}
}

func TestCallbackHandler_Respond_NoInput(t *testing.T) {
	attributes := make(map[string]string)
	attributes["thingMode"] = "test"

	tests := []struct {
		name    string
		handler CallbackHandler
	}{
		{name: "Name", handler: NameCallbackHandler{Name: "Odysseus"}},
		{name: "Password", handler: PasswordCallbackHandler{Password: "password"}},
		{name: "Attribute", handler: AttributeCallbackHandler{Attributes: attributes}},
		{name: "X509Cert", handler: X509CertCallbackHandler{Cert: []byte("12345")}},
	}
	for _, subtest := range tests {
		cb := Callback{}
		t.Run(subtest.name, func(t *testing.T) {
			if err := subtest.handler.Respond(cb); err == nil {
				t.Errorf("Expected an error")
			}
		})
	}
}

func TestPoPCallbackHandler_Respond_MissingEntries(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		cb   Callback
	}{
		{name: "NoInput", cb: Callback{Type: TypeTextInputCallback, Output: make([]entry, 2)}},
		{name: "NoOutput", cb: Callback{Type: TypeTextInputCallback, Input: make([]entry, 2)}},
	}
	handler := PoPCallbackHandler{Hash: crypto.SHA256, Signer: key}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if err := handler.Respond(subtest.cb); err == nil {
				t.Errorf("Expected an error")
			}
		})
	}
}

func TestNameCallbackHandler_Respond(t *testing.T) {
	name := "Odysseus"
	handler := NameCallbackHandler{Name: name}
	cb := dummyCB(TypeNameCallback)
	if err := handler.Respond(cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != name {
		t.Error("Name not updated")
	}
}

func TestPasswordCallbackHandler_Respond(t *testing.T) {
	p := "password"
	handler := PasswordCallbackHandler{Password: p}
	cb := dummyCB(TypeNameCallback)
	if err := handler.Respond(cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != p {
		t.Error("Password not updated")
	}
}

func TestX509CertCallbackHandler_Respond(t *testing.T) {
	c := "12345"
	handler := X509CertCallbackHandler{Cert: []byte(c)}
	cb := dummyCB(TypeNameCallback)
	if err := handler.Respond(cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != c {
		t.Error("Certificate not updated")
	}
}

func TestAttributeCallbackHandler_Respond(t *testing.T) {
	k := "thingMode"
	v := "test"
	attributes := make(map[string]string)
	attributes[k] = v
	handler := AttributeCallbackHandler{attributes}
	cb := dummyCB(TypeNameCallback, k)
	if err := handler.Respond(cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != v {
		t.Error("Attribute not updated")
	}
}

func TestPoPCallbackHandler_Respond(t *testing.T) {
	challenge := "12345"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler := PoPCallbackHandler{crypto.SHA256, key}
	cb := dummyCB(TypeTextInputCallback, PromptProofOfPossessionCallback, challenge)
	if err := handler.Respond(cb); err != nil {
		t.Fatal(err)
	}
	challengeResponse, err := base64.StdEncoding.DecodeString(cb.Input[0].Value)
	if err != nil {
		t.Fatal(err)
	}

	sig := struct {
		R, S *big.Int
	}{}
	_, err = asn1.Unmarshal([]byte(challengeResponse), &sig)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte(challenge))
	if !ecdsa.Verify(&key.PublicKey, d[:], sig.R, sig.S) {
		t.Error("Signature verification has failed")
	}
}

func TestProcessCallbacks(t *testing.T) {
	nameCB := dummyCB(TypeNameCallback)
	nameHandler := NameCallbackHandler{Name: "Odysseus"}
	pwdCB := dummyCB(TypePasswordCallback)

	tests := []struct {
		name      string
		callbacks []Callback
		handlers  []CallbackHandler
		ok        bool
	}{
		{"ok", []Callback{nameCB}, []CallbackHandler{nameHandler}, true},
		{"error", []Callback{pwdCB}, []CallbackHandler{nameHandler}, false},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := processCallbacks(subtest.callbacks, subtest.handlers)
			if subtest.ok && err != nil {
				t.Errorf("unexpected error but got: %v", err)

			} else if !subtest.ok && err == nil {
				t.Errorf("expected an error")

			}
		})
	}
}
