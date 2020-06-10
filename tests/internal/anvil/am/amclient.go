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

package am

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const (
	// Base AM URL
	AMURL = "http://am.localtest.me:8080/am"
	// HTTP header keys
	headerContentType = "Content-Type"
	headerCookie      = "iPlanetDirectoryPro"
	headerAPIVersion  = "Accept-API-Version"
	headerIfNotMatch  = "If-None-Match"
	// AM admin's credentials
	adminUsername = "amadmin"
	adminPassword = "password"
	// endpoint versions
	realmConfigEndpointVersion = "protocol=2.0,resource=1.0"
	userEndpointVersion        = "resource=3.0, protocol=1.0"
)

var DebugLogger = log.New(ioutil.Discard, "", 0)

var httpClient = http.Client{
	Timeout: 30 * time.Second,
}

// crestCreate makes an HTTP POST request with the CREST 'create' action appended to the given endpoint.
func crestCreate(endpoint string, version string, payload io.Reader) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, payload)
	if err != nil {
		return reply, err
	}

	q := req.URL.Query()
	q.Set("_action", "create")
	req.URL.RawQuery = q.Encode()

	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		dumpHTTPRoundTrip(req, res)
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}

	return reply, nil
}

// crestUpdate makes an HTTP PUT request to the given endpoint as described in the CREST update protocol.
func crestUpdate(endpoint string, version string, payload io.Reader) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, payload)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		dumpHTTPRoundTrip(req, res)
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}

	return reply, nil
}

// crestDelete makes an HTTP DELETE request to the given endpoint to the given endpoint.
func crestDelete(endpoint string, version string) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		dumpHTTPRoundTrip(req, res)
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}

	return reply, nil
}

// crestCreate makes an HTTP Put request to the given endpoint to the given endpoint.
func putCreate(endpoint string, version string, payload io.Reader) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodPut, endpoint, payload)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)
	req.Header.Set(headerIfNotMatch, "*")

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		dumpHTTPRoundTrip(req, res)
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}

	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}
	return reply, nil
}

// get makes a GET request to AM with an admin SSO token
func get(endpoint string, version string) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		dumpHTTPRoundTrip(req, res)
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}

	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}
	return reply, nil
}

// getSSOToken gets an SSO token using the AM Admin's credentials
func getSSOToken() (token string, err error) {
	req, err := http.NewRequest(http.MethodPost, AMURL+"/json/realms/root/authenticate", nil)
	if err != nil {
		return token, err
	}
	req.Header.Add(headerAPIVersion, "resource=2.0, protocol=1.0")
	req.Header.Add(headerContentType, "application/json")
	req.Header.Add("X-OpenAM-Username", adminUsername)
	req.Header.Add("X-OpenAM-Password", adminPassword)

	res, err := httpClient.Do(req)
	if err != nil {
		dumpHTTPRoundTrip(req, res)
		return token, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		dumpHTTPRoundTrip(req, res)
		return token, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return token, err
	}

	responseBody := struct {
		TokenID string `json:"tokenId"`
	}{}
	if err := json.Unmarshal(body, &responseBody); err != nil {
		return token, err
	}
	return responseBody.TokenID, nil
}

// CreateRealm creates a realm with the given name
// Returns the realm Id that is required to modify/delete the realm
func CreateRealm(parentPath, realmName string) (realmId string, err error) {
	payload := strings.NewReader(fmt.Sprintf("{\"name\": \"%s\", \"active\": true, \"parentPath\": \"%s\", \"aliases\": []}", realmName, parentPath))
	b, err := crestCreate(AMURL+"/json/global-config/realms", "resource=1.0, protocol=2.0", payload)
	if err != nil {
		return realmId, err
	}
	data := struct {
		Id string `json:"_id"`
	}{}
	err = json.Unmarshal(b, &data)
	return data.Id, err
}

// DeleteRealm deletes the realm with the given Id
func DeleteRealm(realmId string) (err error) {
	_, err = crestDelete(AMURL+"/json/global-config/realms/"+realmId, "resource=1.0, protocol=2.0")
	return err
}

// IdAttributes contains identity attributes
type IdAttributes struct {
	Name                  string             `json:"username"`
	Password              string             `json:"userPassword,omitempty"`
	ThingType             things.ThingType   `json:"thingType,omitempty"`
	ThingKeys             jose.JSONWebKeySet `json:"thingKeys,omitempty"`
	ThingOAuth2ClientName string             `json:"thingOAuth2ClientName,omitempty"`
}

func (id IdAttributes) String() string {
	return fmt.Sprintf("{Name: %s, Password: %s, ThingType: %s, ThingKeys: %v}", id.Name, id.Password, id.ThingType,
		id.ThingKeys)
}

// CreateIdentity creates an identity in the the given realm using the supplied attributes
func CreateIdentity(realm string, attributes IdAttributes) error {
	payload, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	_, err = crestCreate(
		AMURL+"/json/users?realm="+realm,
		userEndpointVersion,
		bytes.NewBuffer(payload))
	return err
}

// GetIdentity gets the identity from AM
func GetIdentity(realm, name string) ([]byte, error) {
	return get(fmt.Sprintf("%s/json/users/%s?realm=%s", AMURL, name, realm), userEndpointVersion)
}

// DeleteIdentity deletes the identity from AM
func DeleteIdentity() (err error) {
	_, err = crestDelete(
		AMURL+"/json/users",
		userEndpointVersion)
	return err
}

// CreateTreeNode creates an auth tree node in the realm
func CreateTreeNode(realm, nodeType, id string, config io.Reader) (err error) {
	_, err = putCreate(
		fmt.Sprintf("%s/json/realm-config/authentication/authenticationtrees/nodes/%s/%s?realm=%s", AMURL, nodeType, id, realm),
		realmConfigEndpointVersion,
		config)
	return err
}

// DeleteTreeNode deletes the auth tree node from the realm
func DeleteTreeNode(realm, nodeType, id string) (err error) {
	_, err = crestDelete(
		fmt.Sprintf("%s/json/realm-config/authentication/authenticationtrees/nodes/%s/%s?realm=%s", AMURL, nodeType, id, realm),
		realmConfigEndpointVersion)
	return err
}

// CreateTree creates an auth tree in the realm
func CreateTree(realm, id string, config io.Reader) (err error) {
	_, err = putCreate(
		fmt.Sprintf("%s/json/realm-config/authentication/authenticationtrees/trees/%s?realm=%s", AMURL, id, realm),
		realmConfigEndpointVersion,
		config)
	return err
}

// DeleteTree deletes the auth tree from the realm
func DeleteTree(realm, id string) (err error) {
	_, err = crestDelete(
		fmt.Sprintf("%s/json/realm-config/authentication/authenticationtrees/trees/%s?realm=%s", AMURL, id, realm),
		realmConfigEndpointVersion)
	return err
}

// CreateService creates a service in the realm
func CreateService(realm, serviceType string, config io.Reader) (err error) {
	_, err = crestCreate(
		fmt.Sprintf("%s/json/realm-config/services/%s?realm=%s", AMURL, serviceType, realm),
		realmConfigEndpointVersion,
		config)
	return err
}

// DeleteService deletes the service from the realm
func DeleteService(realm string, serviceName string) (err error) {
	_, err = crestDelete(
		fmt.Sprintf("%s/json/realm-config/services/%s?realm=%s", AMURL, serviceName, realm),
		realmConfigEndpointVersion)
	return err
}

// CreateAgent creates an agent (OAuth 2.0 Client, JWT Issuer etc) in the realm
func CreateAgent(realm, agentName, payloadPath string) (err error) {
	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}
	_, err = putCreate(
		fmt.Sprintf("%s/json/realm-config/agents/%s?realm=%s", AMURL, agentName, realm),
		realmConfigEndpointVersion,
		bytes.NewReader(b))
	return err
}

// DeleteAgent deletes the agent from the realm
func DeleteAgent(realm string, agentName string) (err error) {
	_, err = crestDelete(
		fmt.Sprintf("%s/json/realm-config/agents/%s?realm=%s", AMURL, agentName, realm),
		realmConfigEndpointVersion)
	return err
}

// CreateScript creates the script in the realm
func CreateScript(realm string, config io.Reader) (err error) {
	_, err = crestCreate(
		fmt.Sprintf("%s/json/scripts?realm=%s", AMURL, realm),
		"protocol=1.0,resource=1.0",
		config)
	return err
}

// DeleteScript deletes the script from the realm
func DeleteScript(realm string, id string) (err error) {
	_, err = crestDelete(
		fmt.Sprintf("%s/json/scripts/%s?realm=%s", AMURL, id, realm),
		"protocol=1.0,resource=1.0")
	return err
}

// UpdateAgent updates an agent's (OAuth 2.0 Client, JWT Issuer etc) configuration in AM
func UpdateAgent(realm, agentName, payloadPath string) (err error) {
	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}
	_, err = crestUpdate(
		fmt.Sprintf("%s/json/realm-config/agents/%s?realm=%s", AMURL, agentName, realm),
		realmConfigEndpointVersion,
		bytes.NewReader(b))
	return err
}

// CreateSecretMapping creates or updates the secret mapping in the default keystore
func CreateSecretMapping(secretID string, aliases []string) (err error) {
	mapping := struct {
		SecretID string   `json:"secretId"`
		Aliases  []string `json:"aliases"`
	}{SecretID: secretID, Aliases: aliases}
	b, err := json.Marshal(mapping)
	if err != nil {
		return err
	}
	_, err = crestUpdate(
		fmt.Sprintf("%s/json/global-config/secrets/stores/KeyStoreSecretStore/default-keystore/mappings/%s", AMURL, secretID),
		"protocol=2.0,resource=1.0",
		bytes.NewReader(b))
	return err
}

func dumpHTTPRoundTrip(req *http.Request, res *http.Response) {
	if req != nil {
		dump, _ := httputil.DumpRequest(req, true)
		DebugLogger.Println(string(dump))
	}
	if res != nil {
		dump, _ := httputil.DumpResponse(res, true)
		DebugLogger.Println(string(dump))
	}
}
