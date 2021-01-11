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

package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	testCookieName              = "iPlanetDirectoryPro"
	testRealm                   = "/testRealm"
	testTree                    = "testTree"
	testHTTPAccessTokenEndpoint = "/json/things/*"
	testHTTPAttributesEndpoint  = "/json/things/*"
)

func testServerInfo() []byte {
	return []byte(fmt.Sprintf(`{"cookieName":"%s"}`, testCookieName))
}

func testServerInfoHTTPMux(code int, response []byte) (mux *http.ServeMux) {
	mux = http.NewServeMux()
	mux.HandleFunc("/json/serverinfo/*", func(writer http.ResponseWriter, request *http.Request) {
		if code != http.StatusOK {
			http.Error(writer, string(response), code)
			return
		}
		_, _ = writer.Write(response)
	})
	return mux
}

// testSetRootCAs sets the root certificate authorities on the AM client as the same as the test server client
// Function is careful not to change any existing transport configuration except the root CAs
func testSetRootCAs(client *amConnection, server *httptest.Server) {
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		transport = &http.Transport{}
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	client.Transport = transport
}

func testAMClientInitialise(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &amConnection{
		baseURL:  server.URL,
		realm:    testRealm,
		authTree: testTree,
	}
	testSetRootCAs(c, server)

	err = c.Initialise()
	if err != nil {
		return err
	}
	// check that the cookName has been set on the struct
	if c.cookieName != testCookieName {
		return errors.New("Cookie name has not been set")
	}
	return nil
}

func TestAMClient_Initialise(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		serverMux  *http.ServeMux
	}{
		{name: "success", successful: true, serverMux: testServerInfoHTTPMux(http.StatusOK, testServerInfo())},
		{name: "not-found", serverMux: testServerInfoHTTPMux(http.StatusNotFound, []byte("Not found"))},
		{name: "invalid-server-info", serverMux: testServerInfoHTTPMux(http.StatusOK, []byte("aaaaaa"))},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testAMClientInitialise(subtest.serverMux)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testAuthHTTPMux(code int, response []byte) (mux *http.ServeMux) {
	mux = testServerInfoHTTPMux(http.StatusOK, testServerInfo())
	mux.HandleFunc("/json/authenticate", func(writer http.ResponseWriter, request *http.Request) {
		// check that the query is correct
		if realm, ok := request.URL.Query()["realm"]; !ok || len(realm) != 1 || realm[0] != testRealm {
			http.Error(writer, "incorrect realm query", http.StatusBadRequest)
		}
		if tree, ok := request.URL.Query()["authIndexValue"]; !ok || len(tree) != 1 || tree[0] != testTree {
			http.Error(writer, "incorrect auth tree query", http.StatusBadRequest)
		}
		if authType, ok := request.URL.Query()["authIndexType"]; !ok || len(authType) != 1 || authType[0] != "service" {
			http.Error(writer, "incorrect auth type query", http.StatusBadRequest)
		}
		if code != http.StatusOK {
			http.Error(writer, string(response), code)
			return
		}
		_, _ = writer.Write(response)
	})
	return mux
}

func testAMClientAuthenticate(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &amConnection{
		baseURL:  server.URL,
		realm:    testRealm,
		authTree: testTree,
	}
	testSetRootCAs(c, server)

	err = c.Initialise()
	if err != nil {
		return err
	}

	reply, err := c.Authenticate(AuthenticatePayload{})
	if err != nil {
		return err
	}
	if !reply.HasSessionToken() {
		return errors.New("Expected reply to have session token")
	}
	return nil
}

func TestAMClient_Authenticate(t *testing.T) {
	info := AuthenticatePayload{
		SessionToken: SessionToken{TokenID: "12345"},
	}
	b, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		successful bool
		serverMux  *http.ServeMux
	}{
		{name: "success", successful: true, serverMux: testAuthHTTPMux(http.StatusOK, b)},
		{name: "not-ok", serverMux: testAuthHTTPMux(http.StatusUnauthorized, []byte("No go"))},
		{name: "invalid-auth-payload", serverMux: testAuthHTTPMux(http.StatusOK, []byte("aaaaaa"))},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testAMClientAuthenticate(subtest.serverMux)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func TestAMClient_AMInfo(t *testing.T) {
	url := "http://same-path.org"
	client := &amConnection{
		baseURL:  url,
		realm:    testRealm,
		authTree: testTree,
	}
	info, err := client.AMInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.Realm != testRealm {
		t.Error("incorrect realm")
	}
	if info.ThingsVersion != thingsEndpointVersion {
		t.Error("incorrect things endpoint version")
	}
	if info.AccessTokenURL != client.accessTokenURL() {
		t.Error("incorrect access token endpoint url")
	}
	if info.AttributesURL != client.attributesURL(nil) {
		t.Error("incorrect attributes endpoint url")
	}
	if info.IntrospectURL != client.introspectURL() {
		t.Error("incorrect introspection endpoint url")
	}
}

func testAccessTokenHTTPMux(code int, response []byte) (mux *http.ServeMux) {
	mux = testServerInfoHTTPMux(http.StatusOK, testServerInfo())
	mux.HandleFunc(testHTTPAccessTokenEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		if code != http.StatusOK {
			http.Error(writer, string(response), code)
			return
		}
		_, _ = writer.Write(response)
	})
	return mux
}

func testAMClientAccessToken(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &amConnection{
		baseURL:  server.URL,
		realm:    testRealm,
		authTree: testTree,
	}
	testSetRootCAs(c, server)

	err = c.Initialise()
	if err != nil {
		return err
	}

	_, err = c.AccessToken("aToken", ApplicationJOSE, "aSignedWT")
	return err
}

func TestAMClient_AccessToken(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		serverMux  *http.ServeMux
	}{
		{name: "success", successful: true, serverMux: testAccessTokenHTTPMux(http.StatusOK, []byte("{}"))},
		{name: "no-go", serverMux: testAccessTokenHTTPMux(http.StatusUnauthorized, []byte("{}"))},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testAMClientAccessToken(subtest.serverMux)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func testAttributesHTTPMux(code int, response []byte) (mux *http.ServeMux) {
	mux = testServerInfoHTTPMux(http.StatusOK, testServerInfo())
	mux.HandleFunc(testHTTPAttributesEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		if code != http.StatusOK {
			http.Error(writer, string(response), code)
			return
		}
		_, _ = writer.Write(response)
	})
	return mux
}

func testAMClientAttributes(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &amConnection{
		baseURL:  server.URL,
		realm:    testRealm,
		authTree: testTree,
	}
	testSetRootCAs(c, server)

	err = c.Initialise()
	if err != nil {
		return err
	}

	_, err = c.Attributes("aToken", ApplicationJOSE, "aSignedWT", []string{})
	return err
}

func TestAMClient_Attributes(t *testing.T) {
	tests := []struct {
		name       string
		successful bool
		serverMux  *http.ServeMux
	}{
		{name: "success", successful: true, serverMux: testAttributesHTTPMux(http.StatusOK, []byte("{}"))},
		{name: "no-go", serverMux: testAttributesHTTPMux(http.StatusUnauthorized, []byte("{}"))},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := testAMClientAttributes(subtest.serverMux)
			if subtest.successful && err != nil {
				t.Error(err)
			}
			if !subtest.successful && err == nil {
				t.Error("Expected an error")
			}
		})
	}
}

func newSigner(kid string, key crypto.Signer) (jose.Signer, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("kid", kid)
	return jws.NewSigner(key, opts)
}

func jwksMUX(kid string, key crypto.Signer, alg jose.SignatureAlgorithm) (*http.ServeMux, error) {
	keySet, err := json.Marshal(jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{{KeyID: kid, Key: key.Public(), Algorithm: string(alg), Use: "sig"}},
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/keys", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write(keySet)
	})
	return mux, nil
}

// dummyAccessToken creates a dummy OAuth 2 access token
func dummyAccessToken(signer jose.Signer, nbf time.Time, exp time.Time, scopes []string) string {
	builder := jwt.Signed(signer).Claims(struct {
		Sub   string   `json:"sub"`
		Exp   int64    `json:"exp"`
		Nbf   int64    `json:"nbf"`
		Scope []string `json:"scope"`
	}{
		Sub:   "thing",
		Nbf:   nbf.Unix(),
		Exp:   exp.Unix(),
		Scope: scopes,
	})
	token, err := builder.CompactSerialize()
	if err != nil {
		log.Fatal(err)
	}
	b, _ := json.Marshal(IntrospectPayload{
		Token: token,
	})
	return string(b)
}

// use local introspection if the AM introspection endpoint can't be reached
func TestAMConnection_IntrospectAccessToken_Locally(t *testing.T) {
	kid := "pop.cnf"
	validKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spoofKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	validSigner, err := newSigner(kid, validKey)
	if err != nil {
		t.Fatal(err)
	}
	spoofSigner, err := newSigner(kid, spoofKey)
	if err != nil {
		t.Fatal(err)
	}
	unknownSigner, err := newSigner("unknown.kid", spoofKey)
	if err != nil {
		t.Fatal(err)
	}

	// create a key server to serve up the JWK set
	keyMux, err := jwksMUX(kid, validKey, jose.ES256)
	if err != nil {
		t.Fatal(err)
	}
	keyServer := httptest.NewServer(keyMux)

	// create demo AM server
	mux := testServerInfoHTTPMux(http.StatusOK, testServerInfo())
	mux.HandleFunc("/oauth2/.well-known/openid-configuration", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte(fmt.Sprintf(`{"jwks_uri":"%s/keys"}`, keyServer.URL)))
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &amConnection{
		baseURL:  server.URL,
		realm:    testRealm,
		authTree: testTree,
	}

	testSetRootCAs(c, server)
	err = c.Initialise()
	if err != nil {
		t.Fatal(err)
	}
	// kill key server
	keyServer.Close()

	scopes := []string{"publish", "subscribe"}

	tests := []struct {
		name    string
		payload string
		active  bool
	}{
		{name: "active", active: true,
			payload: dummyAccessToken(validSigner, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), scopes)},
		{name: "expired", active: false,
			payload: dummyAccessToken(validSigner, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), scopes)},
		{name: "premature", active: false,
			payload: dummyAccessToken(validSigner, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour), scopes)},
		{name: "spoof_signer", active: false,
			payload: dummyAccessToken(spoofSigner, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), scopes)},
		{name: "unknown_signer", active: false,
			payload: dummyAccessToken(unknownSigner, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), scopes)},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			introspectionBytes, err := c.IntrospectAccessToken("ssoToken", ApplicationJSON, subtest.payload)
			if err != nil {
				t.Fatal(err)
			}
			var introspection struct {
				Active bool   `json:"active"`
				Scope  string `json:"scope"` // scopes are return in a space-separated string
			}
			if err = json.Unmarshal(introspectionBytes, &introspection); err != nil {
				t.Fatal(err)
			}
			if introspection.Active != subtest.active {
				t.Errorf("Expected active = %v", subtest.active)
			}
			if subtest.active && !reflect.DeepEqual(scopes, strings.Fields(introspection.Scope)) {
				t.Errorf("expected %v; got %v", scopes, strings.Fields(introspection.Scope))
			}
		})
	}
}
