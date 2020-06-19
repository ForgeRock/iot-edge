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
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	testCookieName              = "iPlanetDirectoryPro"
	testRealm                   = "/testRealm"
	testTree                    = "testTree"
	testHTTPAccessTokenEndpoint = "/json/iot"
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
		writer.Write(response)
		return
	})
	return mux
}

// testSetRootCAs sets the root certificate authorities on the AM client as the same as the test server client
// Function is careful not to change any existing transport configuration except the root CAs
func testSetRootCAs(client *AMClient, server *httptest.Server) {
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

	c := &AMClient{
		BaseURL:  server.URL,
		Realm:    testRealm,
		AuthTree: testTree,
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
		writer.Write(response)
		return
	})
	return mux
}

func testAMClientAuthenticate(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &AMClient{
		BaseURL:  server.URL,
		Realm:    testRealm,
		AuthTree: testTree,
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
		TokenId: "12345",
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
	client := &AMClient{
		BaseURL:  url,
		Realm:    testRealm,
		AuthTree: testTree,
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
}

func testAccessTokenHTTPMux(code int, response []byte) (mux *http.ServeMux) {
	mux = testServerInfoHTTPMux(http.StatusOK, testServerInfo())
	mux.HandleFunc(testHTTPAccessTokenEndpoint, func(writer http.ResponseWriter, request *http.Request) {
		if code != http.StatusOK {
			http.Error(writer, string(response), code)
			return
		}
		writer.Write(response)
		return
	})
	return mux
}

func testAMClientAccessToken(mux *http.ServeMux) (err error) {
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := &AMClient{
		BaseURL:  server.URL,
		Realm:    testRealm,
		AuthTree: testTree,
	}
	testSetRootCAs(c, server)

	err = c.Initialise()
	if err != nil {
		return err
	}

	_, err = c.AccessToken("aToken", "aSignedWT")
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

func Test_parseAMError(t *testing.T) {
	amErr := amError{
		Message: "Boom",
		Reason:  "Bang",
	}
	b, err := json.Marshal(amErr)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		code     int
		response []byte
		expected string
	}{
		{name: "validAMErrorMessage", code: http.StatusInternalServerError, response: b, expected: fmt.Sprintf("%s: %s", amErr.Reason, amErr.Message)},
		{name: "invalidAMErrorMessage", code: http.StatusInternalServerError, response: []byte("aaaa"), expected: fmt.Sprintf("request failed with status code %d", http.StatusInternalServerError)},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			err := parseAMError(subtest.response, subtest.code)
			if err.Error() != subtest.expected {
				t.Errorf("expected %s, got %s", subtest.expected, err.Error())
			}
		})
	}
}
