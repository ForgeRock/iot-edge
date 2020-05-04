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
	"github.com/ForgeRock/iot-edge/pkg/things/realm"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/trees"
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

// url utility functions
func urlGlobalConfig(path ...string) string {
	return AMURL + "/json/global-config/" + strings.Join(path, "/")
}
func urlRealmConfig(r realm.Realm, path ...string) string {
	return AMURL + "/json/" + r.URLPath() + "/realm-config/" + strings.Join(path, "/")
}
func urlRealm(r realm.Realm, path ...string) string {
	return AMURL + "/json/" + r.URLPath() + "/" + strings.Join(path, "/")
}
func urlTreeNodes(r realm.Realm, path ...string) string {
	return urlRealm(r, append([]string{"realm-config/authentication/authenticationtrees/nodes"}, path...)...)
}
func urlTrees(r realm.Realm, path ...string) string {
	return urlRealm(r, append([]string{"realm-config/authentication/authenticationtrees/trees"}, path...)...)
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
		dumpHTTPRoundTrip(req, res)
		return reply, err
	}
	defer res.Body.Close()

	reply, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return reply, err
	}
	if res.StatusCode != http.StatusOK {
		dumpHTTPRoundTrip(req, res)
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

// getSSOToken gets an SSO token using the AM Admin's credentials
func getSSOToken() (token string, err error) {
	req, err := http.NewRequest(http.MethodPost, urlRealm(realm.Root(), "authenticate"), nil)
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

// RealmData holds realm data retrieved from AM
// implements the Sort interface so that the data can be sorted from lowest to topmost realm
type RealmData struct {
	Result []struct {
		Id         string `json:"_id"`
		Name       string `json:"name"`
		ParentPath string `json:"parentPath"`
	} `json:"result"`
}

// numberOfParents returns the number of parents that a realm has
func (d RealmData) numberOfParents(i int) (num int) {
	if d.Result[i].Name == "/" {
		return 0
	}
	var r rune
	for _, r = range d.Result[i].ParentPath {
		if r == '/' {
			num += 1
		}
	}
	// differentiate between  "/" = one parent, "/12345abcde" = two parents
	if r != '/' {
		num += 1
	}
	return num
}

func (d RealmData) Len() int {
	return len(d.Result)
}

func (d RealmData) Less(i, j int) bool {
	return d.numberOfParents(i) > d.numberOfParents(j)
}

func (d RealmData) Swap(i, j int) {
	d.Result[i], d.Result[j] = d.Result[j], d.Result[i]
}

// GetRealms retrieves all the realms in the AM instance
func GetRealms() (data RealmData, err error) {
	url := urlGlobalConfig("realms?_queryFilter=true")
	b, err := crestRead(url, "protocol=2.0,resource=1.0")
	if err != nil {
		return data, err
	}
	err = json.Unmarshal(b, &data)
	return data, err
}

// CreateRealm creates a realm with the given name
// Returns the realm Id that is required to modify/delete the realm
func CreateRealm(parentPath, realmName string) (err error) {
	payload := strings.NewReader(fmt.Sprintf("{\"name\": \"%s\", \"active\": true, \"parentPath\": \"%s\", \"aliases\": []}", realmName, parentPath))
	_, err = crestCreate(urlGlobalConfig("realms"), "resource=1.0, protocol=2.0", payload)
	return err
}

// DeleteRealm deletes the realm with the given Id
func DeleteRealm(realmId string) (err error) {
	_, err = crestDelete(urlGlobalConfig("realms", realmId), "resource=1.0, protocol=2.0")
	return err
}

// IdAttributes contains identity attributes
type IdAttributes struct {
	Name                  string             `json:"username"`
	Password              string             `json:"userPassword,omitempty"`
	ThingType             string             `json:"thingType,omitempty"`
	ThingKeys             jose.JSONWebKeySet `json:"thingKeys,omitempty"`
	ThingOAuth2ClientName string             `json:"thingOAuth2ClientName,omitempty"`
}

func (id IdAttributes) String() string {
	return fmt.Sprintf("{Name: %s, Password: %s, ThingType: %s, ThingKeys: %v}", id.Name, id.Password, id.ThingType,
		id.ThingKeys)
}

// CreateIdentity creates an identity in the the given realm using the supplied attributes
func CreateIdentity(r realm.Realm, attributes IdAttributes) error {
	payload, err := json.Marshal(attributes)
	if err != nil {
		return err
	}
	_, err = crestCreate(
		urlRealm(r, "users"),
		userEndpointVersion,
		bytes.NewBuffer(payload))
	return err
}

// DeleteIdentity deletes the identity from AM
func DeleteIdentity(r realm.Realm, name string) (err error) {
	_, err = crestDelete(
		urlRealm(r, "users", name),
		userEndpointVersion)
	return err
}

// CreateTreeNode creates an auth tree node in the realm
func CreateTreeNode(r realm.Realm, node trees.Node) (err error) {
	_, err = putCreate(
		urlTreeNodes(r, node.Type, node.Id),
		realmConfigEndpointVersion,
		bytes.NewReader(node.Config))
	return err
}

// DeleteTreeNode deletes the auth tree node from the realm
func DeleteTreeNode(r realm.Realm, node trees.Node) (err error) {
	_, err = crestDelete(
		urlTreeNodes(r, node.Type, node.Id),
		realmConfigEndpointVersion)
	return err
}

// CreateTree creates an auth tree in the realm
func CreateTree(r realm.Realm, tree trees.Tree) (err error) {
	_, err = putCreate(
		urlTrees(r, tree.Id),
		realmConfigEndpointVersion,
		bytes.NewReader(tree.Config))
	return err
}

// DeleteTree deletes the auth tree from the realm
func DeleteTree(r realm.Realm, tree trees.Tree) (err error) {
	_, err = crestDelete(
		urlTrees(r, tree.Id),
		realmConfigEndpointVersion)
	return err
}

// CreateService creates a service in the realm
func CreateService(r realm.Realm, serviceName, payloadPath string) (err error) {
	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}
	_, err = crestCreate(
		urlRealmConfig(r, "services/"+serviceName),
		realmConfigEndpointVersion,
		bytes.NewReader(b))
	return err
}

// DeleteService deletes the service from the realm
func DeleteService(r realm.Realm, serviceName string) (err error) {
	_, err = crestDelete(
		urlRealmConfig(r, "services/"+serviceName),
		realmConfigEndpointVersion)
	return err
}

// CreateAgent creates an agent (OAuth 2.0 Client, JWT Issuer etc) in the realm
func CreateAgent(r realm.Realm, agentName, payloadPath string) (err error) {
	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}
	_, err = putCreate(
		urlRealmConfig(r, "agents/"+agentName),
		realmConfigEndpointVersion,
		bytes.NewReader(b))
	return err
}

// DeleteAgent deletes the agent from the realm
func DeleteAgent(r realm.Realm, agentName string) (err error) {
	_, err = crestDelete(
		urlRealmConfig(r, "agents/"+agentName),
		realmConfigEndpointVersion)
	return err
}

// UpdateAgent updates an agent's (OAuth 2.0 Client, JWT Issuer etc) configuration in AM
func UpdateAgent(r realm.Realm, agentName, payloadPath string) (err error) {
	b, err := ioutil.ReadFile(payloadPath)
	if err != nil {
		return err
	}
	_, err = crestUpdate(
		urlRealmConfig(r, "agents/"+agentName),
		realmConfigEndpointVersion,
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
