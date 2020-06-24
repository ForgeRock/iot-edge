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

// Package anvil runs functional tests for the IoT SDK
package anvil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"github.com/dchest/uniuri"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const (
	runStr  = "=== RUN"
	passStr = "--- PASS:"
	failStr = "--- FAIL:"

	// Standard timeout used in SDK calls in tests
	StdTimeOut = 10 * time.Second
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
			if err != nil {
				return err
			}
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
			NotBefore:    time.Now(),
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

// TestIEC creates a test IEC
func TestIEC(realm string, authTree string) (*things.IEC, error) {
	jwk, signer, err := GenerateConfirmationKey(jose.ES256)
	if err != nil {
		return nil, err
	}
	attributes := am.IdAttributes{
		Name:      "iec-" + RandomName(),
		Password:  RandomName(),
		ThingType: "iec",
		ThingKeys: jwk,
	}
	err = am.CreateIdentity(realm, attributes)
	if err != nil {
		return nil, err
	}
	return things.NewIEC(am.AMURL, realm, authTree, []things.Handler{
		things.AuthenticateHandler{ThingID: attributes.Name, ConfirmationKeyID: signer.KID, ConfirmationKey: signer.Signer},
	}), nil
}

// ThingData holds information about a Thing used in a test
type ThingData struct {
	Id           am.IdAttributes
	Signer       SigningKey
	Certificates []*x509.Certificate
}

// TestState contains client and realm data required to run a test
type TestState interface {
	// Realm returns the current test realm
	Realm() string
	// ClientType returns 'am' or 'iec' depending on the type of client
	ClientType() string
	// Builder returns a thing builder, which builder is returned is dependant on the client used for the test
	Builder(thingAuthTree string) things.Builder
}

// AMTestState contains data and methods for testing the AM client
type AMTestState struct {
	TestRealm string
}

func (a *AMTestState) ClientType() string {
	return "am"
}

func (a *AMTestState) Builder(thingAuthTree string) things.Builder {
	return things.AMThing(am.AMURL, a.TestRealm, thingAuthTree).SetTimeout(StdTimeOut)
}

func (a *AMTestState) Realm() string {
	return a.TestRealm
}

// IECTestState contains data and methods for testing the IEC client
type IECTestState struct {
	IEC       *things.IEC
	TestRealm string
}

func (i *IECTestState) ClientType() string {
	return "iec"
}

// SetIECAuthTree sets the auth tree used by the test IEC
func (i *IECTestState) SetIECAuthTree(thingAuthTree string) {
	i.IEC.Thing.Client.(*things.AMClient).AuthTree = thingAuthTree
}

func (i *IECTestState) Builder(thingAuthTree string) things.Builder {
	// set thing auth tree on the test IEC
	i.SetIECAuthTree(thingAuthTree)

	// create a new IEC client
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return things.IECThing(i.IEC.Address(), key).SetTimeout(StdTimeOut)
}

func (i *IECTestState) Realm() string {
	return i.TestRealm
}

// SDKTest defines the interface required by a SDK API test
type SDKTest interface {
	Setup(state TestState) (data ThingData, ok bool) // setup actions before the test starts
	Run(state TestState, data ThingData) bool        // function that runs and validates the test
	Cleanup(state TestState, data ThingData)         // cleanup actions after the test has finished
	NameSuffix() string                              // optional suffix to add to struct name to create the test name
}

// NopSetupCleanup defines a struct with no-op Setup and Cleanup methods
type NopSetupCleanup struct {
}

// Setup is a no op function
func (t NopSetupCleanup) Setup() bool {
	return true
}

// Cleanup is a no op function
func (t NopSetupCleanup) Cleanup(TestState, ThingData) {
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
		data.Id.Password = RandomName()
	}
	return data, am.CreateIdentity(realm, data.Id) == nil
}

// GetIdentityAttributes gets the identity and unmarshals its attributes into the supplied struct
func GetIdentityAttributes(realm, name string, attributes interface{}) error {
	response, err := am.GetIdentity(realm, name)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(response, &attributes); err != nil {
		return err
	}
	return nil
}

// resultSprint formats the result string output for a test
func resultSprint(pass bool, testName string, startTime time.Time) string {
	var resStr string
	if pass {
		resStr = passStr
	} else {
		resStr = failStr
	}
	return fmt.Sprintf("%-10s%s (%.2fs)\n", resStr, testName, time.Since(startTime).Seconds())
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

// NewFileDebugger creates a new Anvil logger that logs to file with the given test name
func NewFileDebugger(directory, testName string) (*log.Logger, *os.File) {
	err := os.MkdirAll(directory, 0777)
	if err != nil {
		log.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(directory, testName+".log"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal(err)
	}
	DebugLogger = log.New(file, "", log.Ltime|log.Lmicroseconds|log.Lshortfile)
	return DebugLogger, file
}

// RunTest runs the given SDKTest
func RunTest(state TestState, t SDKTest) (pass bool) {
	name := TestName(t)
	ProgressLogger.Printf("%-10s%s\n", runStr, name)
	start := time.Now()
	defer func() {
		ProgressLogger.Print(resultSprint(pass, name, start))
	}()
	var data ThingData
	if data, pass = t.Setup(state); !pass {
		return false
	}
	DebugLogger.Printf("*** STARTING TEST RUN in realm %s\n", state.Realm())
	pass = t.Run(state, data)
	DebugLogger.Printf("*** RUN RESULT: %v\n\n\n", pass)
	t.Cleanup(state, data)
	return
}
