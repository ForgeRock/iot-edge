/*
 * Copyright 2020-2022 ForgeRock AS
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

// Package anvil runs functional tests for the IoT SDK
package anvil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/gateway"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"github.com/dchest/uniuri"
	jose "gopkg.in/square/go-jose.v2"
)

const (
	PassString = "\033[1;32mPASS\033[0m"
	FailString = "\033[1;31mFAIL\033[0m"

	// Standard timeout used in SDK calls in tests
	StdTimeOut = 10 * time.Second

	RootRealm = "/"

	GatewayClientType = "gateway"
	AMClientType      = "am"
)

var DebugLogger = log.New(ioutil.Discard, "", 0)
var ProgressLogger = log.New(os.Stdout, "", 0)

// CreateRealmHierarchy creates the supplied realms in a linear hierarchy
// The first realm is a child of root, otherwise a realm is a child of the previously created realm
// Returns the fully-qualified name of the leaf realm and a list of ids of all the created realms
func CreateRealmHierarchy(names ...string) (fullName string, ids []string, err error) {
	ids = make([]string, len(names))
	parentPath := "/"
	for i, name := range names {
		fullName = parentPath + name
		// store realm ids in reverse order i.e. child to parent order
		ids[len(names)-i-1], err = am.CreateRealm(parentPath, name)
		if err != nil {
			return fullName, ids, err
		}
		parentPath += name + "/"
	}
	return fullName, ids, nil
}

// CreateRealmWithAlias creates a test realm with an alias
func CreateRealmWithAlias(name string, alias string) (id string, err error) {
	return am.CreateRealm("/", name, alias)
}

// CreateRealmWithDNSAlias creates a test realm with a DNS alias
func CreateRealmWithDNSAlias(name string, alias string) (id string, err error) {
	id, err = am.CreateRealm("/", name, alias)
	if err != nil {
		return id, err
	}
	serverProperties, err := am.GetAdvancedServerProperties()
	if err != nil {
		return id, err
	}

	key := fmt.Sprintf("com.sun.identity.server.fqdnMap[%s]", alias)
	serverProperties[key] = alias
	err = am.SetAdvancedServerProperties(serverProperties)
	return id, err
}

// nameWithoutExtension returns the name of the file without the file extension
func nameWithoutExtension(path string) string {
	_, file := filepath.Split(path)
	return strings.TrimSuffix(file, filepath.Ext(file))
}

// parentName returns the name of the directory that contains the file described by the path
func parentName(path string) string {
	return filepath.Base(filepath.Dir(path))
}

// forAllJSONFilesInDirectory calls the supplied function for all JSON files in the given directory, including subdirectories
func forAllJSONFilesInDirectory(dirname string, f func(path string) error) error {
	if _, err := os.Stat(dirname); err != nil {
		return nil
	}
	info, err := ioutil.ReadDir(dirname)
	if err != nil {
		return err
	}
	for _, i := range info {
		path := filepath.Join(dirname, i.Name())
		if i.IsDir() {
			err = forAllJSONFilesInDirectory(path, f)
		} else if filepath.Ext(i.Name()) == ".json" {
			err = f(path)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// ConfigureTestRealm configures the realm by loading all the data in the testDataDir
func ConfigureTestRealm(realm string, testDataDir string) (err error) {
	// add scripts
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "scripts"),
		func(path string) error {
			config, err := os.Open(path)
			if err != nil {
				return err
			}
			defer config.Close()
			return am.CreateScript(realm, config)
		})
	if err != nil {
		return err
	}

	// add tree nodes
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "nodes"),
		func(path string) error {
			config, err := os.Open(path)
			if err != nil {
				return err
			}
			defer config.Close()
			return am.CreateTreeNode(realm, parentName(path), nameWithoutExtension(path), config)
		})
	if err != nil {
		return err
	}

	// add trees
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "trees"),
		func(path string) error {
			config, err := os.Open(path)
			if err != nil {
				return err
			}
			defer config.Close()
			return am.CreateTree(realm, nameWithoutExtension(path), config)
		})
	if err != nil {
		return err
	}

	// create services
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "services"),
		func(path string) error {
			config, err := os.Open(path)
			if err != nil {
				return err
			}
			defer config.Close()
			return am.CreateService(realm, parentName(path), config)
		})
	if err != nil {
		return err
	}

	// update the OAuth 2.0 Client with test specific config
	err = am.UpdateAgent(realm, "OAuth2Client/forgerock-iot-oauth2-client",
		filepath.Join(testDataDir, "agents/forgerock-iot-oauth2-client.json"))
	if err != nil {
		return err
	}
	// create thing OAuth 2.0 Client for thing specific config
	err = am.CreateAgent(realm, "OAuth2Client/thing-oauth2-client",
		filepath.Join(testDataDir, "agents/thing-oauth2-client.json"))
	if err != nil {
		return err
	}

	return nil
}

// RestoreTestRealm restores the configuration of the realm to a pre-test state
func RestoreTestRealm(realm string, testDataDir string) (err error) {
	// delete the various services
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "services"),
		func(path string) error {
			return am.DeleteService(realm, parentName(path))
		})
	if err != nil {
		return err
	}

	// delete the OAuth 2.0 agents
	for _, agent := range []string{"OAuth2Client/forgerock-iot-oauth2-client", "OAuth2Client/thing-oauth2-client", "TrustedJwtIssuer/forgerock-iot-jwt-issuer"} {
		err = am.DeleteAgent(realm, agent)
		if err != nil {
			return err
		}

	}

	// remove the trees
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "trees"),
		func(path string) error {
			return am.DeleteTree(realm, nameWithoutExtension(path))
		})
	if err != nil {
		return err
	}

	// delete the tree nodes
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "nodes"),
		func(path string) error {
			return am.DeleteTreeNode(realm, parentName(path), nameWithoutExtension(path))
		})
	if err != nil {
		return err
	}

	// delete the scripts
	err = forAllJSONFilesInDirectory(
		filepath.Join(testDataDir, "scripts"),
		func(path string) error {
			return am.DeleteScript(realm, nameWithoutExtension(path))
		})
	if err != nil {
		return err
	}
	return nil
}

// URL returns an AM URL that points at the given sub-domain
func URL(subDomain string) *url.URL {
	u, _ := url.Parse(am.URL(subDomain))
	return u
}

// BaseURL returns the root realm URL of AM
func BaseURL() *url.URL {
	u, _ := url.Parse(am.AMURL)
	return u
}

const oauth2Service = "oauth-oidc"

func subConfig(config map[string]json.RawMessage, key string) (sub map[string]json.RawMessage, err error) {
	value, ok := config[key]
	if !ok {
		return sub, fmt.Errorf("missing key %s", key)
	}
	err = json.Unmarshal(value, &sub)
	return sub, err
}

// AccessTokenType is used to configure the type of OAuth2 access token issues by AM
type AccessTokenType struct {
	name string
	alg  jose.SignatureAlgorithm
}

func (a AccessTokenType) Name() string {
	return a.name
}

var (
	// CTS based (stateful) access token type
	CTS = AccessTokenType{name: "CTS"}
	// Client based (stateless) encrypted access token type
	ClientEncrypted = AccessTokenType{name: "ClientEncrypted"}
)

// ClientSignedTokenType returns a client based (stateless) signed token type
func ClientSignedTokenType(alg jose.SignatureAlgorithm) AccessTokenType {
	return AccessTokenType{
		name: "ClientSigned" + string(alg),
		alg:  alg,
	}
}

// ModifyOAuth2Provider changes the OAuth 2.0 access tokens issued by AM
// Returns the original configuration so that the provider can be restored
func ModifyOAuth2Provider(realm string, tokenType AccessTokenType) (original []byte, err error) {
	const (
		coreKey     = "coreOAuth2Config"
		advancedKey = "advancedOAuth2Config"
	)
	clientBased := tokenType != CTS
	original, err = am.GetService(realm, oauth2Service)
	var config, coreConfig, advancedConfig map[string]json.RawMessage
	err = json.Unmarshal(original, &config)
	if err != nil {
		return original, err
	}
	coreConfig, err = subConfig(config, coreKey)
	if err != nil {
		return original, err
	}
	coreConfig["statelessTokensEnabled"], _ = json.Marshal(clientBased)
	newCore, err := json.Marshal(coreConfig)
	if err != nil {
		return original, err
	}
	config[coreKey] = newCore

	advancedConfig, err = subConfig(config, advancedKey)
	if err != nil {
		return original, err
	}
	if tokenType == ClientEncrypted {
		advancedConfig["tokenEncryptionEnabled"], _ = json.Marshal(true)
	}
	if tokenType.alg != "" {
		advancedConfig["tokenSigningAlgorithm"], _ = json.Marshal(tokenType.alg)
	}
	newAdvanced, err := json.Marshal(advancedConfig)
	if err != nil {
		return original, err
	}
	config[advancedKey] = newAdvanced
	newConfig, err := json.Marshal(config)
	if err != nil {
		return original, err
	}
	_, err = am.UpdateService(realm, oauth2Service, bytes.NewReader(newConfig))
	return original, err
}

// RestoreOAuth2Service restores the OAut 2.0 service using the supplied config
func RestoreOAuth2Service(realm string, config []byte) error {
	_, err := am.UpdateService(realm, oauth2Service, bytes.NewReader(config))
	return err
}

// RevokeAccessToken uses the custom OAuth 2.0 client to revoke the access token
func RevokeAccessToken(realm string, token string) error {
	return am.RevokeAccessToken(realm, "thing-oauth2-client", "a@xoS2#7M6hFChR#d4$%", token)
}

// DeleteRealms deletes all the realms in the id slice from the AM instance
// Assumes that the ids are in an order that can be safely deleted e.g. children before parents
func DeleteRealms(ids []string) (err error) {
	for _, id := range ids {
		err = am.DeleteRealm(id)
		if err != nil {
			return err
		}
	}
	return nil
}

// CreateCertVerificationMapping maps the IoT certification verification secret to the test key
func CreateCertVerificationMapping() error {
	return am.CreateSecretMapping("am.services.iot.cert.verification", []string{"es256test"})
}

// CertVerificationKey returns the test JSON web key used by AM to verify certificates
func CertVerificationKey() (*jose.JSONWebKey, error) {
	ec256TestBytes := []byte(`{"kty": "EC",
		"kid": "Fol7IpdKeLZmzKtCEgi1LDhSIzM=",
		"x": "N7MtObVf92FJTwYvY2ZvTVT3rgZp7a7XDtzT_9Rw7IA",
		"y": "uxNmyoocPopYh4k1FCc41yuJZVohxlhMo3KTIJVTP3c",
		"crv": "P-256",
		"alg": "ES256",
		"d": "w9rAMaNcP7cA0e5SECc4Tk1PDQEY66ml9y9-6E8fmR4",
		"x5c": ["MIIBwjCCAWkCCQCw3GyPBTSiGzAJBgcqhkjOPQQBMGoxCzAJBgNVBAYTAlVLMRAwDgYDVQQIEwdCcmlzdG9sMRAwDgYDVQQHEwdCcmlzdG9sMRIwEAYDVQQKEwlGb3JnZVJvY2sxDzANBgNVBAsTBk9wZW5BTTESMBAGA1UEAxMJZXMyNTZ0ZXN0MB4XDTE3MDIwMzA5MzQ0NloXDTIwMTAzMDA5MzQ0NlowajELMAkGA1UEBhMCVUsxEDAOBgNVBAgTB0JyaXN0b2wxEDAOBgNVBAcTB0JyaXN0b2wxEjAQBgNVBAoTCUZvcmdlUm9jazEPMA0GA1UECxMGT3BlbkFNMRIwEAYDVQQDEwllczI1NnRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ3sy05tV/3YUlPBi9jZm9NVPeuBmntrtcO3NP/1HDsgLsTZsqKHD6KWIeJNRQnONcriWVaIcZYTKNykyCVUz93MAkGByqGSM49BAEDSAAwRQIgZhTox7WpCb9krZMyHfgCzHwfu0FVqaJsO2Nl2ArhCX0CIQC5GgWD5jjCRlIWSEFSDo4DZgoQFXaQkJUSUbJZYpi9dA=="]
	}`)
	var key jose.JSONWebKey
	if err := json.Unmarshal(ec256TestBytes, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

var maxSerialNumber = new(big.Int).Exp(big.NewInt(2), big.NewInt(159), nil)

// CreateCertificate creates a certificate for a Thing signed by the given CA JSON web key
func CreateCertificate(caWebKey *jose.JSONWebKey, thingID string, thingKey crypto.Signer) (*x509.Certificate, error) {
	// check that server web key contains a certificate
	if len(caWebKey.Certificates) == 0 {
		return nil, fmt.Errorf("server WebKey does not contain a certificate")
	}

	serialNumber, err := rand.Int(rand.Reader, maxSerialNumber)
	if err != nil {
		return nil, err
	}

	cert, err := x509.CreateCertificate(rand.Reader,
		&x509.Certificate{
			SerialNumber: serialNumber,
			Subject:      pkix.Name{CommonName: thingID},
			NotBefore:    time.Now().Add(-24 * time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		},
		caWebKey.Certificates[0],
		thingKey.Public(),
		caWebKey.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(cert)
}

// TestGateway creates a test IoT Gateway
func TestGateway(u *url.URL, realm string, audience string, authTree string, dnsConfigured bool) (*gateway.Gateway, error) {
	jwk, signer, err := ConfirmationKey(jose.ES256)
	if err != nil {
		return nil, err
	}
	attributes := am.IdAttributes{
		Name:      "gateway-" + RandomName(),
		Password:  RandomName(),
		ThingType: "gateway",
		ThingKeys: jwk,
	}
	attributes, err = am.CreateIdentity(realm, attributes)
	if err != nil {
		return nil, err
	}
	testRealm := ""
	if !dnsConfigured {
		testRealm = realm
	}
	return gateway.New(u.String(), testRealm, authTree, StdTimeOut, []callback.Handler{
		callback.AuthenticateHandler{
			Audience: audience,
			ThingID:  attributes.Name,
			KeyID:    signer.KID,
			Key:      signer.Signer},
	}), nil
}

// ThingData holds information about a Thing used in a test
type ThingData struct {
	Id           am.IdAttributes
	Signer       SigningKey
	Certificates []*x509.Certificate
}

// TestState contains client and realm data required to run a test
type TestState struct {
	clientType    string
	gateway       *gateway.Gateway
	realm         string
	realmPath     string
	amURL         *url.URL
	dnsConfigured bool
}

// NewTestState will create a new TestState instance with the given properties
func NewTestState(gateway *gateway.Gateway, amURL *url.URL, realm, realmPath string, dns bool) TestState {
	clientType := AMClientType
	if gateway != nil {
		clientType = GatewayClientType
	}
	return TestState{
		clientType:    clientType,
		gateway:       gateway,
		realm:         realm,
		realmPath:     realmPath,
		amURL:         amURL,
		dnsConfigured: dns,
	}
}

// SetGatewayTree sets the auth tree used by the test IoT Gateway
func (t *TestState) SetGatewayTree(tree string) {
	if t.clientType == GatewayClientType {
		gateway.SetAuthenticationTree(t.gateway, tree)
	}
}

// ConnectionURL of the current test server (AM or Gateway)
func (t *TestState) ConnectionURL() *url.URL {
	if t.clientType == GatewayClientType {
		u, _ := url.Parse("coap://" + t.gateway.Address())
		return u
	}
	return t.amURL
}

// ClientType returns 'am' or 'gateway' depending on the type of client
func (t *TestState) ClientType() string {
	return t.clientType
}

// RealmForConfiguration returns the realm that can be used for test setup, validation and clean up
func (t *TestState) RealmForConfiguration() string {
	return t.realm
}

// Realm returns the test realm that should be passed to the IoT SDK
func (t *TestState) Realm() string {
	if t.clientType == GatewayClientType || t.dnsConfigured {
		return ""
	}
	return t.realm
}

// RealmPath returns the path of the current test realm
func (t *TestState) RealmPath() string {
	return t.realmPath
}

// DNSConfigured will be true if DNS configuration is used instead of a realm path
func (t *TestState) DNSConfigured() bool {
	return t.dnsConfigured
}

// AMURL returns the URL of the AM server as a string
func (t *TestState) AMURL() string {
	return t.amURL.String()
}

func (t *TestState) String() string {
	return fmt.Sprintf("\nConfig Realm: %s\nRealm: %s\nRealm Path: %s\nClient Type: %s\nURL: %s\n",
		t.RealmForConfiguration(), t.Realm(), t.RealmPath(), t.ClientType(), t.ConnectionURL().String())
}

// SDKTest defines the interface required by a SDK API test
type SDKTest interface {
	Setup(state TestState) (data ThingData, ok bool)     // setup actions before the test starts
	Run(state TestState, data ThingData) bool            // function that runs and validates the test
	Cleanup(state TestState, data ThingData) (err error) // cleanup actions after the test has finished
	NameSuffix() string                                  // optional suffix to add to struct name to create the test name
}

// NopSetupCleanup defines a struct with no-op Setup and Cleanup methods
type NopSetupCleanup struct {
}

// Setup is a no op function
func (t NopSetupCleanup) Setup() bool {
	return true
}

// Cleanup is a no op function
func (t NopSetupCleanup) Cleanup(TestState, ThingData) error {
	return nil
}

// NameSuffix returns the empty string
func (t NopSetupCleanup) NameSuffix() string {
	return ""
}

// Create an identity in AM from the supplied data
// uses sensible defaults for certain fields if none have been set
func CreateIdentity(realm string, data ThingData) (ThingData, bool) {
	if data.Id.Name == "" {
		data.Id.Name = RandomName()
	}
	if data.Id.Password == "" {
		data.Id.Password = "5tr0ngG3n3r@ted"
	}
	var err error
	data.Id, err = am.CreateIdentity(realm, data.Id)
	return data, err == nil
}

// CreateUser creates a human identity in AM with a unique name.
func CreateUser(realm string) (am.IdAttributes, error) {
	attributes := am.IdAttributes{
		Name:     RandomName(),
		Password: "5tr0ngG3n3r@ted",
	}
	return am.CreateIdentity(realm, attributes)
}

// resultSprint formats the result string output for a test
func resultSprint(pass bool, testName string, startTime time.Time) string {
	var resStr string
	if pass {
		resStr = PassString
	} else {
		resStr = FailString
	}
	return fmt.Sprintf("--- %s: %s (%.2fs)\n", resStr, testName, time.Since(startTime).Seconds())
}

// RandomName returns a random string
func RandomName() string {
	return uniuri.New()
}

// TypeName returns the name of the type after removing the package prefix
func TypeName(t interface{}) string {
	nameSlice := strings.Split(reflect.TypeOf(t).String(), ".")
	return nameSlice[len(nameSlice)-1]
}

// TestName returns the name of the test
func TestName(t SDKTest) string {
	return TypeName(t) + t.NameSuffix()
}

// RunTest runs the given SDKTest
func RunTest(state TestState, t SDKTest) (pass bool) {
	name := TestName(t)
	ProgressLogger.Printf("=== RUN   %s\n", name)
	start := time.Now()
	defer func() {
		ProgressLogger.Print(resultSprint(pass, name, start))
	}()
	var data ThingData
	if data, pass = t.Setup(state); !pass {
		return false
	}
	DebugLogger.Printf("*** STARTING TEST RUN: %v", state)
	pass = t.Run(state, data)
	DebugLogger.Printf("*** RUN RESULT: %v\n\n\n", pass)
	if err := t.Cleanup(state, data); err != nil {
		DebugLogger.Printf("clean up error; %v", err)
	}
	return
}
