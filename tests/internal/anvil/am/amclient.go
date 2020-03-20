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
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/tests/internal/anvil/trees"
	"gopkg.in/square/go-jose.v2"
)

const (
	// Base AM URL
	AMURL = "http://openam.iectest.com:8080/openam"
	// HTTP header keys
	headerContentType = "Content-Type"
	headerCookie      = "iPlanetDirectoryPro"
	headerAPIVersion  = "Accept-API-Version"
	headerIfNotMatch  = "If-None-Match"
	// AM admin's credentials
	adminUsername = "amadmin"
	adminPassword = "password"
)

var httpClient = http.Client{
	Timeout: 30 * time.Second,
}

// url utility functions
func urlGlobalConfig(path ...string) string {
	return AMURL + "/json/global-config/" + strings.Join(path, "/")
}
func urlRealm(realm string, path ...string) string {
	return AMURL + "/json/realms/root/realms/" + realm + "/" + strings.Join(path, "/")
}
func urlTreeNodes(realm string, path ...string) string {
	return urlRealm(realm, append([]string{"realm-config/authentication/authenticationtrees/nodes"}, path...)...)
}
func urlTrees(realm string, path ...string) string {
	return urlRealm(realm, append([]string{"realm-config/authentication/authenticationtrees/trees"}, path...)...)
}

// URLAuthenticate returns the URL for an Auth tree in the given realm
func URLAuthenticate(realm, tree string) string {
	return fmt.Sprintf("%s/json/authenticate?realm=%s&authIndexType=service&authIndexValue=%s", AMURL, realm, tree)
}

// URLIoT returns the URL for the IoT endpoint in the given realm
func URLIoT(realm string) string {
	return fmt.Sprintf("%s/json/realms/root/realms/%s/iot", AMURL, realm)
}

// crestCreate makes an HTTP POST request with the CREST 'create' action appended to the given endpoint.
func crestCreate(endpoint string, version string, payload io.Reader) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodPost, endpoint+"/?_action=create", payload)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		return reply, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
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
		return reply, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
	}
	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}

	return reply, nil
}

// crestRead makes an HTTP GET request to the given endpoint to the given endpoint.
func crestRead(endpoint string, version string) (reply []byte, err error) {
	// get SSO token
	ssoToken, err := getSSOToken()
	if err != nil {
		return reply, err
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return reply, err
	}
	req.Header.Set(headerContentType, "application/json")
	req.Header.Set(headerCookie, ssoToken)
	req.Header.Set(headerAPIVersion, version)

	res, err := httpClient.Do(req)
	if err != nil {
		return reply, err
	}
	defer res.Body.Close()

	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}
	if res.StatusCode != http.StatusOK {
		return reply, fmt.Errorf("unexpected status code: %v", res.StatusCode)
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
		return reply, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
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
	req, err := http.NewRequest(http.MethodPost, urlRealm("root", "authenticate"), nil)
	if err != nil {
		return token, err
	}
	req.Header.Add(headerAPIVersion, "resource=2.0, protocol=1.0")
	req.Header.Add(headerContentType, "application/json")
	req.Header.Add("X-OpenAM-Username", adminUsername)
	req.Header.Add("X-OpenAM-Password", adminPassword)

	res, err := httpClient.Do(req)
	if err != nil {
		return token, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
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
func CreateRealm(realm string) (id string, err error) {
	payload := strings.NewReader(fmt.Sprintf("{\"name\": \"%s\", \"active\": true, \"parentPath\": \"/\", \"aliases\": []}", realm))
	var reply []byte
	reply, err = crestCreate(urlGlobalConfig("realms"), "resource=1.0, protocol=2.0", payload)
	realmData := struct {
		Id string `json:"_id"`
	}{}
	if err := json.Unmarshal(reply, &realmData); err != nil {
		return id, err
	}
	return realmData.Id, nil
}

// DeleteRealm deletes the realm with the given Id
func DeleteRealm(realmId string) (err error) {
	_, err = crestDelete(urlGlobalConfig("realms", realmId), "resource=1.0, protocol=2.0")
	return err
}

// IdAttributes contains identity attributes
type IdAttributes struct {
	Name      string             `json:"username"`
	Password  string             `json:"userPassword,omitempty"`
	ThingType string             `json:"thingType,omitempty"`
	ThingKeys jose.JSONWebKeySet `json:"thingKeys,omitempty"`
}

func (id IdAttributes) String() string {
	return fmt.Sprintf("{Name: %s, Password: %s, ThingType: %s, ThingKeys: %v}", id.Name, id.Password, id.ThingType,
		id.ThingKeys)
}

// CreateIdentity creates an identity in the the given realm using the supplied attributes
func CreateIdentity(realmName string, attributes IdAttributes) error {
	payload, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	_, err = crestCreate(
		urlRealm(realmName, "users"),
		"resource=3.0, protocol=1.0",
		bytes.NewBuffer(payload))
	return err
}

// DeleteIdentity deletes the identity from AM
func DeleteIdentity(realmName string, name string) (err error) {
	_, err = crestDelete(
		urlRealm(realmName, "users", name),
		"resource=3.0, protocol=1.0")
	return err
}

// CreateTreeNode creates an Auth Tree node in AM
func CreateTreeNode(realmName string, node trees.Node) (err error) {
	_, err = putCreate(
		urlTreeNodes(realmName, node.Type, node.Id),
		"resource=1.0, protocol=2.0",
		bytes.NewReader(node.Config))
	return err
}

// CreateTree creates an Auth Tree in AM
func CreateTree(realmName string, tree trees.Tree) (err error) {
	_, err = putCreate(
		urlTrees(realmName, tree.Id),
		"resource=1.0, protocol=2.0",
		bytes.NewReader(tree.Config))
	return err
}
