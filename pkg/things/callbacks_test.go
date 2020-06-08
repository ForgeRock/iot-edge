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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"gopkg.in/square/go-jose.v2"
	"math/big"
	"testing"
	"time"
)

var testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var testKID = "testKID"

type mockThingIdentity struct {
}

func (id mockThingIdentity) ConfirmationKey() SigningKey {
	return SigningKey{testKID, testKey}
}

func (id mockThingIdentity) Realm() string {
	return "testRealm"
}

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

func TestCallbackHandler_HandleResult(t *testing.T) {
	tests := []struct {
		name    string
		cb      Callback
		handler Handler
		err     error
	}{
		// NameHandler
		{name: "Name/ok", cb: dummyCB(TypeNameCallback), handler: NameHandler{Name: "Odysseus"}, err: nil},
		{name: "Name/notHandled", cb: dummyCB(TypeTextInputCallback), handler: NameHandler{Name: "Odysseus"}, err: errNotHandled},
		// PasswordHandler
		{name: "Password/ok", cb: dummyCB(TypePasswordCallback), handler: PasswordHandler{Password: "password"}, err: nil},
		{name: "Password/notHandled", cb: dummyCB(TypeTextInputCallback), handler: PasswordHandler{Password: "password"}, err: errNotHandled},
		// AuthenticateHandler
		{name: "Authenticate/notHandled", cb: dummyCB(TypeNameCallback), handler: AuthenticateHandler{ThingID: "Odysseus"}, err: errNotHandled},
		{name: "Register/notHandled", cb: dummyCB(TypeNameCallback), handler: RegisterHandler{ThingID: "Odysseus"}, err: errNotHandled},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if got := subtest.handler.Handle(nil, subtest.cb); got != subtest.err {
				t.Errorf("Handle() = %v, want %v", got, subtest.err)
			}
		})
	}
}

func TestCallbackHandler_Respond_NoInput(t *testing.T) {
	tests := []struct {
		name    string
		handler Handler
	}{
		{name: "Name", handler: NameHandler{Name: "Odysseus"}},
		{name: "Password", handler: PasswordHandler{Password: "password"}},
	}
	for _, subtest := range tests {
		cb := Callback{}
		t.Run(subtest.name, func(t *testing.T) {
			if err := subtest.handler.Handle(nil, cb); err == nil {
				t.Errorf("Expected an error")
			}
		})
	}
}

func TestNameCallbackHandler_Respond(t *testing.T) {
	name := "Odysseus"
	handler := NameHandler{Name: name}
	cb := dummyCB(TypeNameCallback)
	if err := handler.Handle(mockThingIdentity{}, cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != name {
		t.Error("Name not updated")
	}
}

func TestPasswordCallbackHandler_Respond(t *testing.T) {
	p := "password"
	handler := PasswordHandler{Password: p}
	cb := dummyCB(TypePasswordCallback)
	if err := handler.Handle(mockThingIdentity{}, cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != p {
		t.Error("Password not updated")
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
			err := ProcessCallbacks(mockThingIdentity{}, subtest.handlers, subtest.callbacks)
			if subtest.ok && err != nil {
				t.Errorf("unexpected error but got: %v", err)

			} else if !subtest.ok && err == nil {
				t.Errorf("expected an error")

			}
		})
	}
}

func TestAuthenticateHandler_Handle(t *testing.T) {
	thingID := "thingOne"
	h := AuthenticateHandler{ThingID: thingID}
	cb := jwtVerifyCB(false)
	if err := h.Handle(mockThingIdentity{}, cb); err != nil {
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
	if claims.Sub != thingID {
		t.Fatal("missing subject")
	}
	if claims.Aud == "" {
		t.Fatal("missing audience")
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
	if claims.CNF.KID != testKID {
		t.Fatal("incorrect KID")
	}
}

func TestRegisterHandler_Handle(t *testing.T) {
	thingID := "thingOne"
	serialNumber := "12345"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: thingID},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	h := RegisterHandler{ThingID: thingID, ThingType: TypeDevice, Certificates: []*x509.Certificate{cert},
		Claims: func() interface{} {
			return struct {
				SerialNumber string `json:"serialNumber"`
			}{SerialNumber: serialNumber}
		}}
	cb := jwtVerifyCB(true)
	if err := h.Handle(mockThingIdentity{}, cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value
	claims := struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		CNF struct {
			JWK *jose.JSONWebKey `json:"jwk,omitempty"`
		} `json:"cnf"`
		ThingType    string `json:"thingType"`
		Iat          int64  `json:"iat"`
		Exp          int64  `json:"exp"`
		Nonce        string `json:"nonce"`
		SerialNumber string `json:"serialNumber"`
	}{}
	err = extractJWTPayload(response, &claims)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != thingID {
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
	if claims.CNF.JWK == nil {
		t.Fatal("missing JWT")
	}
	if claims.CNF.JWK.Key == nil {
		t.Fatal("missing JWT-Key")
	}
	if claims.CNF.JWK.KeyID == "" {
		t.Fatal("missing JWT-KeyID")
	}
	if len(claims.CNF.JWK.Certificates) == 0 {
		t.Fatal("missing JWT-Certs")
	}
	if claims.SerialNumber != serialNumber {
		t.Fatal("incorrect serial number")
	}
}
