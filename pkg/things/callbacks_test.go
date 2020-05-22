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
	"gopkg.in/square/go-jose.v2"
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
		Output: make([]Entry, l),
		Input:  make([]Entry, l),
	}
	for i, p := range prompts {
		cb.Output[i].Value = p
	}
	return cb
}

func jwtVerifyCB(register bool) Callback {
	id := "jwt-pop-authentication"
	if register {
		id = "jwt-pop-registration"
	}
	return Callback{
		Type:   "HiddenValueCallback",
		Output: []Entry{{Name: "value", Value: "12345"}, {Name: "id", Value: id}},
		Input:  []Entry{{Name: "IDToken1", Value: "jwt-pop-authentication"}},
	}
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
		handler Handler
		want    bool
	}{
		// NameHandler
		{name: "Name/True", cb: dummyCB(TypeNameCallback), handler: NameHandler{Name: "Odysseus"}, want: true},
		{name: "Name/False", cb: dummyCB(TypeTextInputCallback), handler: NameHandler{Name: "Odysseus"}, want: false},
		// PasswordHandler
		{name: "Password/True", cb: dummyCB(TypePasswordCallback), handler: PasswordHandler{Password: "password"}, want: true},
		{name: "Password/False", cb: dummyCB(TypeTextInputCallback), handler: PasswordHandler{Password: "password"}, want: false},
		// AttributeHandler
		{name: "Attribute/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: AttributeHandler{Attributes: attributes}, want: false},
		{name: "Attribute/False/WrongType", cb: dummyCB(TypeNameCallback), handler: AttributeHandler{Attributes: attributes}, want: false},
		{name: "Attribute/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: AttributeHandler{Attributes: attributes}, want: false},
		{name: "Attribute/True", cb: dummyCB(TypeTextInputCallback, "thingMode"), handler: AttributeHandler{Attributes: attributes}, want: true},
		// X509CertificateHandler
		{name: "X509Cert/False/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: X509CertificateHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/False/WrongType", cb: dummyCB(TypeNameCallback, PromptX509CertCallback), handler: X509CertificateHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: X509CertificateHandler{Cert: []byte("12345")}, want: false},
		{name: "X509Cert/True", cb: dummyCB(TypeTextInputCallback, PromptX509CertCallback), handler: X509CertificateHandler{Cert: []byte("12345")}, want: true},
		// ProofOfPossessionCallbackHandler
		{name: "ProofOfPossession/False/NoOutput", cb: Callback{Type: TypeTextInputCallback}, handler: PoPHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/False/WrongType", cb: dummyCB(TypeNameCallback, PromptProofOfPossessionCallback), handler: PoPHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/False/WrongPrompt", cb: dummyCB(TypeTextInputCallback, "Wrong prompt"), handler: PoPHandler{Hash: crypto.SHA256, Signer: key}, want: false},
		{name: "ProofOfPossession/True", cb: dummyCB(TypeTextInputCallback, PromptProofOfPossessionCallback), handler: PoPHandler{Hash: crypto.SHA256, Signer: key}, want: true},
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
		handler Handler
	}{
		{name: "Name", handler: NameHandler{Name: "Odysseus"}},
		{name: "Password", handler: PasswordHandler{Password: "password"}},
		{name: "Attribute", handler: AttributeHandler{Attributes: attributes}},
		{name: "X509Cert", handler: X509CertificateHandler{Cert: []byte("12345")}},
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
		{name: "NoInput", cb: Callback{Type: TypeTextInputCallback, Output: make([]Entry, 2)}},
		{name: "NoOutput", cb: Callback{Type: TypeTextInputCallback, Input: make([]Entry, 2)}},
	}
	handler := PoPHandler{Hash: crypto.SHA256, Signer: key}
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
	handler := NameHandler{Name: name}
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
	handler := PasswordHandler{Password: p}
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
	handler := X509CertificateHandler{Cert: []byte(c)}
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
	handler := AttributeHandler{attributes}
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
	handler := PoPHandler{crypto.SHA256, key}
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
	nameHandler := NameHandler{Name: "Odysseus"}
	pwdCB := dummyCB(TypePasswordCallback)

	tests := []struct {
		name      string
		callbacks []Callback
		handlers  []Handler
		ok        bool
	}{
		{"ok", []Callback{nameCB}, []Handler{nameHandler}, true},
		{"error", []Callback{pwdCB}, []Handler{nameHandler}, false},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := ProcessCallbacks(subtest.callbacks, subtest.handlers)
			if subtest.ok && err != nil {
				t.Errorf("unexpected error but got: %v", err)

			} else if !subtest.ok && err == nil {
				t.Errorf("expected an error")

			}
		})
	}
}

func TestJWTAssertion_Match(t *testing.T) {
	handler := JWTPoPAuthHandler{}
	if !handler.Match(jwtVerifyCB(false)) {
		t.Error("expected true")
	}
}

func TestJWTAssertion_Respond(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "testKID"
	h := JWTPoPAuthHandler{KID: kid, Signer: key, ThingId: "thingOne", Realm: "/", ThingType: "device"}
	cb := jwtVerifyCB(false)
	if err := h.Respond(cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value
	claims := struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		CNF struct {
			KID string `json:"kid"`
		} `json:"cnf"`
		ThingType string `json:"thingType"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
		Nonce     string `json:"nonce"`
	}{}
	err = extractJWTPayload(response, &claims)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub == "" {
		t.Fatal("missing subject")
	}
	if claims.Aud == "" {
		t.Fatal("missing audience")
	}
	if claims.ThingType != "device" {
		t.Fatal("missing thing type")
	}
	if claims.Iat == 0 {
		t.Fatal("missing issue time")
	}
	if claims.Exp == 0 {
		t.Fatal("missing expiry time")
	}
	if claims.Nonce == "" {
		t.Fatal("missing nonce")
	}
	if claims.CNF.KID != kid {
		t.Fatal("incorrect kid")
	}
}

func TestJWTPoPRegHandler_Match(t *testing.T) {
	handler := JWTPoPRegHandler{}
	if !handler.Match(jwtVerifyCB(true)) {
		t.Error("expected true")
	}
}

func TestJWTPoPRegHandler_Respond(t *testing.T) {

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := "testKID"
	h := JWTPoPRegHandler{KID: kid, Signer: key, ThingId: "thingOne", Realm: "/", ThingType: "device"}
	cb := jwtVerifyCB(false)
	if err := h.Respond(cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value
	claims := struct {
		Sub       string `json:"sub"`
		Aud       string `json:"aud"`
		ThingType string `json:"thingType"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
		Nonce     string `json:"nonce"`
		CNF       struct {
			JWK jose.JSONWebKey `json:"jwk"`
		} `json:"cnf"`
	}{}
	err = extractJWTPayload(response, &claims)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub == "" {
		t.Error("missing subject")
	}
	if claims.Aud == "" {
		t.Error("missing audience")
	}
	if claims.ThingType != "device" {
		t.Error("missing thing type")
	}
	if claims.Iat == 0 {
		t.Error("missing issue time")
	}
	if claims.Exp == 0 {
		t.Error("missing expiry time")
	}
	if claims.Nonce == "" {
		t.Error("missing nonce")
	}
	if claims.CNF.JWK.KeyID == "" {
		t.Error("missing JWK:KID")
	}
}
