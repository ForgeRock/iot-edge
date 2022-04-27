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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"gopkg.in/square/go-jose.v2"
)

var (
	testKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
)

const (
	testKID   = "testKID"
	testRealm = "testRealm"
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

func jwtCB(id string) Callback {
	return Callback{
		Type:   "HiddenValueCallback",
		Output: []Entry{{Name: "value", Value: "12345"}, {Name: "id", Value: id}},
		Input:  []Entry{{Name: "IDToken1", Value: id}},
	}
}

func TestCallbackHandler_HandleResult(t *testing.T) {
	tests := []struct {
		name    string
		cb      Callback
		handler Handler
		handled bool
	}{
		// NameHandler
		{name: "Name/ok", cb: dummyCB(TypeNameCallback), handler: NameHandler{Name: "Odysseus"}, handled: true},
		{name: "Name/notHandled", cb: dummyCB(TypeTextInputCallback), handler: NameHandler{Name: "Odysseus"}, handled: false},
		// PasswordHandler
		{name: "Password/ok", cb: dummyCB(TypePasswordCallback), handler: PasswordHandler{Password: "password"}, handled: true},
		{name: "Password/notHandled", cb: dummyCB(TypeTextInputCallback), handler: PasswordHandler{Password: "password"}, handled: false},
		// AuthenticateHandler
		{name: "Authenticate/notHandled", cb: dummyCB(TypeNameCallback), handler: AuthenticateHandler{ThingID: "Odysseus"}, handled: false},
		{name: "Register/notHandled", cb: dummyCB(TypeNameCallback), handler: RegisterHandler{ThingID: "Odysseus"}, handled: false},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if handled, _ := subtest.handler.Handle(subtest.cb); handled != subtest.handled {
				t.Errorf("Handle() = %v, want %v", handled, subtest.handled)
			}
		})
	}
}

func TestCallbackHandler_Respond_NoInput(t *testing.T) {
	tests := []struct {
		name    string
		handler Handler
		cb      Callback
	}{
		{name: "Name", handler: NameHandler{Name: "Odysseus"}, cb: Callback{Type: TypeNameCallback}},
		{name: "Password", handler: PasswordHandler{Password: "password"}, cb: Callback{Type: TypePasswordCallback}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if _, err := subtest.handler.Handle(subtest.cb); err == nil {
				t.Errorf("Expected an error")
			}
		})
	}
}

func TestNameCallbackHandler_Respond(t *testing.T) {
	name := "Odysseus"
	handler := NameHandler{Name: name}
	cb := dummyCB(TypeNameCallback)
	if _, err := handler.Handle(cb); err != nil {
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
	if _, err := handler.Handle(cb); err != nil {
		t.Fatal(err)
	}
	if cb.Input[0].Value != p {
		t.Error("Password not updated")
	}
}

func TestAuthenticateHandler_Handle(t *testing.T) {
	thingID := "thingOne"
	lue := "42"
	h := AuthenticateHandler{
		Audience: testRealm,
		ThingID:  thingID,
		KeyID:    testKID,
		Key:      testKey,
		Claims: func() interface{} {
			return struct {
				LifeUniverseEverything string `json:"life_universe_everything"`
			}{LifeUniverseEverything: lue}
		}}
	cb := jwtCB("jwt-pop-authentication")
	if _, err := h.Handle(cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value.(string)
	claims := struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		CNF struct {
			KID string `json:"kid"`
		} `json:"cnf"`
		ThingType              string `json:"thingType"`
		Iat                    int64  `json:"iat"`
		Exp                    int64  `json:"exp"`
		Nonce                  string `json:"nonce"`
		LifeUniverseEverything string `json:"life_universe_everything"` // custom value
	}{}
	err := jws.ExtractClaims(response, &claims)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != thingID {
		t.Fatal("missing subject")
	}
	if claims.Aud != testRealm {
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
	if claims.LifeUniverseEverything != lue {
		t.Fatal("incorrect custom claim")
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
	h := RegisterHandler{
		Audience:     testRealm,
		ThingID:      thingID,
		ThingType:    TypeDevice,
		KeyID:        testKID,
		Key:          key,
		Certificates: []*x509.Certificate{cert}, Claims: func() interface{} {
			return struct {
				SerialNumber string `json:"serialNumber"`
			}{SerialNumber: serialNumber}
		}}
	cb := jwtCB("jwt-pop-registration")
	if _, err := h.Handle(cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value.(string)
	claims := struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		CNF struct {
			JWK *jose.JSONWebKey `json:"jwk,omitempty"`
			KID string           `json:"kid"`
		} `json:"cnf"`
		ThingType    string `json:"thingType"`
		Iat          int64  `json:"iat"`
		Exp          int64  `json:"exp"`
		Nonce        string `json:"nonce"`
		SerialNumber string `json:"serialNumber"`
	}{}
	err = jws.ExtractClaims(response, &claims)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Sub != thingID {
		t.Fatal("missing subject")
	}
	if claims.Aud != testRealm {
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
	if claims.CNF.KID != testKID {
		t.Fatal("missing CNF-KID")
	}
	if claims.SerialNumber != serialNumber {
		t.Fatal("incorrect serial number")
	}
}

func TestRegisterHandler_Handle_SoftwareStatement(t *testing.T) {
	softwareStatement := "qwertyuiop"
	h := RegisterHandler{SoftwareStatement: softwareStatement}
	cb := jwtCB("software_statement")
	if _, err := h.Handle(cb); err != nil {
		t.Fatal(err)
	}
	response := cb.Input[0].Value.(string)
	if response != softwareStatement {
		t.Fatal("missing software statement")
	}
}

func TestCallback_ID(t *testing.T) {
	tests := []struct {
		name     string
		cb       Callback
		expected string
	}{
		{name: "ok", cb: Callback{Type: TypeHiddenValueCallback, Output: []Entry{{Name: keyHiddenID, Value: "foo"}}}, expected: "foo"},
		{name: "notFirst", cb: Callback{Type: TypeHiddenValueCallback, Output: []Entry{{Name: "prompt", Value: "bar"}, {Name: keyHiddenID, Value: "foo"}}}, expected: "foo"},
		{name: "malformed", cb: Callback{Type: TypeHiddenValueCallback, Output: []Entry{{Name: keyHiddenID, Value: true}}}, expected: ""},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			id := subtest.cb.ID()
			if id != subtest.expected {
				t.Errorf("ID() = %v, want %v", id, subtest.expected)
			}
		})
	}
}

func TestEntry_Unmarshal(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "string", raw: `{"key":"value"}`},
		{name: "bool", raw: `{"key":true}`},
		{name: "number", raw: `{"key":2.718}`},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			var e Entry
			if err := json.Unmarshal([]byte(subtest.raw), &e); err != nil {
				t.Errorf("unmarshal into entry failed; %v", err)
			}
		})
	}

}
