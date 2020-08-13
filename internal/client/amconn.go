// +build !coap,!http http

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
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/internal/introspect"
	"gopkg.in/square/go-jose.v2"
)

const (
	acceptAPIVersion          = "Accept-API-Version"
	serverInfoEndpointVersion = "resource=1.1"
	authNEndpointVersion      = "protocol=1.0,resource=2.1"
	thingsEndpointVersion     = "protocol=2.0,resource=1.0"
	sessionEndpointVersion    = "resource=4.0"
	httpContentType           = "Content-Type"
	// Query keys
	fieldQueryKey         = "_fields"
	realmQueryKey         = "realm"
	authIndexTypeQueryKey = "authIndexType"
	authTreeQueryKey      = "authIndexValue"
)

// newSessionRequest returns a new session request
func (c *amConnection) newSessionRequest(tokenID string, action string) (request *http.Request, err error) {
	request, err = http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/json/sessions?_action=%s", c.baseURL, action),
		nil)
	if err != nil {
		return nil, err
	}

	request.Header.Add(acceptAPIVersion, sessionEndpointVersion)
	request.Header.Add(httpContentType, string(ApplicationJSON))
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokenID})
	return request, nil
}

// logoutSession represented by the given token
func (c *amConnection) LogoutSession(tokenID string) (err error) {
	request, err := c.newSessionRequest(tokenID, "logout")
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return err
	}

	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return fmt.Errorf("session logout failed")
	}
	return nil
}

// validateSession represented by the given token
func (c *amConnection) ValidateSession(tokenID string) (ok bool, err error) {
	request, err := c.newSessionRequest(tokenID, "validate")
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return false, err
	}

	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return false, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return false, nil
	default:
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return false, fmt.Errorf("session validation failed")
	}

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return false, err
	}
	info := struct {
		Valid bool `json:"valid"`
	}{}
	if err = json.Unmarshal(responseBody, &info); err != nil {
		return false, err
	}
	return info.Valid, nil

}

// amError is used to unmarshal an AM error response
type amError struct {
	Code    int    `json:"code"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

func (e amError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Message)
}

func parseAMError(response []byte, status int) error {
	var amError amError
	if err := json.Unmarshal(response, &amError); err != nil {
		return fmt.Errorf("request failed with status code %d", status)
	}
	if amError.Code == http.StatusUnauthorized {
		return ErrUnauthorised
	}
	return amError
}

// initialise checks that the server can be reached and prepares the client for further communication
func (c *amConnection) Initialise() error {
	info, err := c.getServerInfo()
	if err != nil {
		return err
	}
	c.cookieName = info.CookieName
	_ = c.updateJSONWebKeySet()
	return nil
}

// authenticate with the AM authTree using the given payload
// This is a single round trip
func (c *amConnection) Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, c.baseURL+"/json/authenticate", bytes.NewBuffer(requestBody))
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return reply, err
	}

	// add realm and auth tree to query
	q := request.URL.Query()
	if c.realm != "" {
		q.Set(realmQueryKey, c.realm)
	}
	q.Set(authIndexTypeQueryKey, "service")
	q.Set(authTreeQueryKey, c.authTree)
	request.URL.RawQuery = q.Encode()

	request.Header.Add(acceptAPIVersion, authNEndpointVersion)
	request.Header.Add(httpContentType, string(ApplicationJSON))
	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, ErrUnauthorised
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	if err = json.Unmarshal(responseBody, &reply); err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return reply, err
	}
	return reply, err
}

// serverInfo contains information gathered from a server information request to AM
type serverInfo struct {
	CookieName string `json:"cookieName"`
}

// getServerInfo makes a server information request to AM
func (c *amConnection) getServerInfo() (info serverInfo, err error) {
	request, err := http.NewRequest(http.MethodGet, c.baseURL+"/json/serverinfo/*", nil)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return info, err
	}

	q := request.URL.Query()
	q.Set(fieldQueryKey, "cookieName")
	request.URL.RawQuery = q.Encode()

	request.Header.Add(acceptAPIVersion, serverInfoEndpointVersion)
	request.Header.Add(httpContentType, string(ApplicationJSON))
	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, fmt.Errorf("server info request failed")
	}
	if err = json.Unmarshal(responseBody, &info); err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return info, err
	}
	return info, err
}

// getJWKSURI gets the OAuth 2.0 JSON Web Key set URI from AM
func (c *amConnection) getJWKSURI() (uri string, err error) {
	u := c.baseURL + "/oauth2/.well-known/openid-configuration"
	if c.realm != "" {
		u = u + "?realm=" + c.realm
	}
	request, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return uri, err
	}

	request.Header.Add(httpContentType, string(ApplicationJSON))
	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return uri, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return uri, err
	}
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return uri, fmt.Errorf("openid-configuration request failed")
	}
	var config struct {
		URI string `json:"jwks_uri"`
	}
	if err = json.Unmarshal(responseBody, &config); err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return uri, err
	}
	return config.URI, err
}

// updateJSONWebKeySet updates the local JWK Set by retrieving the current key set from AM
func (c *amConnection) updateJSONWebKeySet() (err error) {
	uri, err := c.getJWKSURI()
	if err != nil {
		return err
	}
	request, err := http.NewRequest(http.MethodGet, uri, nil)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return err
	}

	request.Header.Add(httpContentType, string(ApplicationJSON))
	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return err
	}
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return fmt.Errorf("OAuth 2.0 JSON Web Key set request failed")
	}
	if err = json.Unmarshal(responseBody, &c.accessTokenJWKS); err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return err
	}
	return nil
}

func (c *amConnection) accessTokenURL() string {
	q := "_action=get_access_token"
	if c.realm != "" {
		q += "&realm=" + c.realm
	}
	return c.baseURL + "/json/things/*?" + q
}

func (c *amConnection) attributesURL(names []string) string {
	q := make([]string, 0)
	if c.realm != "" {
		q = append(q, "realm="+c.realm)
	}
	if len(names) > 0 {
		q = append(q, "_fields="+strings.Join(names, ","))
	}

	u := c.baseURL + "/json/things/*"
	if len(q) == 0 {
		return u
	}
	return u + "?" + strings.Join(q, "&")
}

// amInfo returns AM related information to the client
func (c *amConnection) AMInfo() (info AMInfoResponse, err error) {
	return AMInfoResponse{
		Realm:          c.realm,
		AccessTokenURL: c.accessTokenURL(),
		AttributesURL:  c.attributesURL(nil),
		ThingsVersion:  thingsEndpointVersion,
	}, nil
}

// AccessToken makes an access token request with the given session token and payload
func (c *amConnection) AccessToken(tokenID string, content ContentType, payload string) ([]byte, error) {
	request, err := http.NewRequest(http.MethodPost, c.accessTokenURL(), strings.NewReader(payload))
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return nil, err
	}
	return c.makeCommandRequest(tokenID, content, request)
}

// IntrospectAccessToken introspects an access token locally
func (c *amConnection) IntrospectAccessToken(token string) (introspection []byte, err error) {
	object, err := jose.ParseSigned(token)
	if err != nil {
		return introspection, err
	}
	if len(object.Signatures) == 0 {
		return introspection, fmt.Errorf("expected at least one signature header")
	}
	header := object.Signatures[0].Header

	// can not introspect symmetrically signed tokens locally
	switch jose.SignatureAlgorithm(header.Algorithm) {
	case jose.HS256, jose.HS384, jose.HS512:
		return introspection, fmt.Errorf("symmetrically signed tokens unsupported")
	}

	if header.KeyID == "" {
		return introspection, fmt.Errorf("no kid")
	}
	keys := c.accessTokenJWKS.Key(header.KeyID)

	// if keys is empty then we don't have the token key locally, get updated JWK set
	if len(keys) == 0 {
		debug.Logger.Println("updating JSON web key set")
		err = c.updateJSONWebKeySet()
		if err != nil {
			return introspection, err
		}
		keys = c.accessTokenJWKS.Key(header.KeyID)
		if len(keys) == 0 {
			// unknown key, return inactive introspection
			debug.Logger.Printf("unknown access token key: %s", header.KeyID)
			return introspect.InactiveIntrospectionBytes, nil
		}
	}
	for _, key := range keys {
		introspection, err = object.Verify(key)
		if err == nil {
			break
		}
	}
	if err != nil {
		return introspection, err
	}
	if !introspect.ValidNow(introspection) {
		return introspect.InactiveIntrospectionBytes, nil
	}
	return introspect.AddActive(introspection)
}

// attributes makes a thing attributes request with the given session token and payload
func (c *amConnection) Attributes(tokenID string, content ContentType, payload string, names []string) (reply []byte, err error) {
	request, err := http.NewRequest(http.MethodGet, c.attributesURL(names), strings.NewReader(payload))
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, nil))
		return nil, err
	}
	return c.makeCommandRequest(tokenID, content, request)
}

func (c *amConnection) makeCommandRequest(tokenID string, content ContentType, request *http.Request) (reply []byte, err error) {
	request.Header.Set(acceptAPIVersion, thingsEndpointVersion)
	request.Header.Set(httpContentType, string(content))
	request.AddCookie(&http.Cookie{Name: c.cookieName, Value: tokenID})
	response, err := c.Do(request)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		debug.Logger.Println(debug.DumpHTTPRoundTrip(request, response))
		return responseBody, parseAMError(responseBody, response.StatusCode)
	}
	return responseBody, err
}

// SetAuthenticationTree changes the authentication tree that the connection was created with.
// This is a convenience function for functional testing.
func SetAuthenticationTree(connection Connection, tree string) {
	connection.(*amConnection).authTree = tree
}
