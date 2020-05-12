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
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/pkg/things/realm"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/trees"
	"github.com/dchest/uniuri"
	"gopkg.in/square/go-jose.v2"
	"io/ioutil"
	"log"
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
	StdTimeOut = 5 * time.Second
)

var DebugLogger = log.New(ioutil.Discard, "", 0)
var ProgressLogger = log.New(os.Stdout, "", 0)

// CreateTestRealm creates a realm with a random name
// level indicates how many realms are above it e.g. a realm at level 1 is a child of the root realm
// For level > 1, the number of necessary parent realms are created
func CreateTestRealm(level uint) (ids []string, r realm.Realm, err error) {
	if level == 0 {
		return ids, nil, fmt.Errorf("invalid level")
	}
	ids = make([]string, level)
	parent := realm.Root()
	for ; level > 0; level-- {
		r = realm.SubRealm(parent, RandomName())
		// store realm ids in reverse order i.e. child to parent order
		ids[level-1], err = am.CreateRealm(r.ParentPath(), r.Name())
		if err != nil {
			return ids, r, err
		}
		parent = r
	}
	return ids, r, nil
}

// ConfigureTestRealm configures the realm by loading all the data in the testDataDir
func ConfigureTestRealm(r realm.Realm, testDataDir string) (err error) {
	// add tree nodes
	nodes, err := trees.ReadNodes(filepath.Join(testDataDir, "nodes"))
	if err != nil {
		return err
	}
	for _, node := range nodes {
		err = am.CreateTreeNode(r, node)
		if err != nil {
			return err
		}
	}

	// add trees
	loadTrees, err := trees.ReadTrees(filepath.Join(testDataDir, "trees"))
	if err != nil {
		return err
	}
	for _, tree := range loadTrees {
		err = am.CreateTree(r, tree)
		if err != nil {
			return err
		}
	}

	// add IoT Service
	err = am.CreateService(r, "iot", filepath.Join(testDataDir, "services/iot.json"))
	if err != nil {
		return err
	}
	// add OAuth 2.0 Service
	err = am.CreateService(r, "oauth-oidc", filepath.Join(testDataDir, "services/oauth2.json"))
	if err != nil {
		return err
	}
	// update the OAuth 2.0 Client with test specific config
	err = am.UpdateAgent(r, "OAuth2Client/forgerock-iot-oauth2-client",
		filepath.Join(testDataDir, "agents/forgerock-iot-oauth2-client.json"))
	if err != nil {
		return err
	}
	// create thing OAuth 2.0 Client for thing specific config
	err = am.CreateAgent(r, "OAuth2Client/thing-oauth2-client",
		filepath.Join(testDataDir, "agents/thing-oauth2-client.json"))
	if err != nil {
		return err
	}

	return nil
}

// RestoreTestRealm restores the configuration of the realm to a pre-test state
func RestoreTestRealm(r realm.Realm, testDataDir string) (err error) {
	// delete the various services
	for _, service := range []string{"oauth-oidc", "iot"} {
		err = am.DeleteService(r, service)
		if err != nil {
			return err
		}
	}

	// delete the OAuth 2.0 agents
	for _, agent := range []string{"OAuth2Client/forgerock-iot-oauth2-client", "OAuth2Client/thing-oauth2-client", "TrustedJwtIssuer/forgerock-iot-jwt-issuer"} {
		err = am.DeleteAgent(r, agent)
		if err != nil {
			return err
		}

	}

	// remove the trees
	loadTrees, err := trees.ReadTrees(filepath.Join(testDataDir, "trees"))
	if err != nil {
		return err
	}
	for _, tree := range loadTrees {
		err = am.DeleteTree(r, tree)
		if err != nil {
			return err
		}
	}

	// delete the tree nodes
	nodes, err := trees.ReadNodes(filepath.Join(testDataDir, "nodes"))
	if err != nil {
		return err
	}
	for _, node := range nodes {
		err = am.DeleteTreeNode(r, node)
		if err != nil {
			return err
		}
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

// TestIEC creates a test IEC
func TestIEC(r realm.Realm) (*things.IEC, error) {
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
	err = am.CreateIdentity(r, attributes)
	if err != nil {
		return nil, err
	}
	return things.NewDefaultIEC(signer, am.AMURL, r, attributes.Name, attributes.Password), nil
}

// ThingData holds information about a Thing used in a test
type ThingData struct {
	Id     am.IdAttributes
	Signer crypto.Signer
}

// TestState contains client and realm data required to run a test
type TestState interface {
	// Realm returns the current test realm
	Realm() realm.Realm
	// InitClients initialises the test clients (multiple clients in the case of IEC tests)
	// and returns a new client to be used for testing
	InitClients(thingAuthTree string) things.Client
}

type amTestState struct {
	r realm.Realm
}

func (a *amTestState) InitClients(authTree string) things.Client {
	t := things.NewAMClient(am.AMURL, a.r, authTree)
	t.Timeout = StdTimeOut
	return t
}

func (a *amTestState) Realm() realm.Realm {
	return a.r
}

// AMClientTestContext returns a test state for testing the AM client
func AMClientTestState(r realm.Realm) TestState {
	return &amTestState{r: r}
}

type iecTestState struct {
	iec *things.IEC
	r   realm.Realm
}

func (i *iecTestState) InitClients(authTree string) things.Client {
	// set thing auth tree on the test IEC
	_ = i.iec.ThingClient.(*things.AMClient).SetAuthTree(authTree)
	// create a new IEC client
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := things.NewIECClient(i.iec.Address(), key)
	c.Timeout = StdTimeOut
	return c
}

func (i *iecTestState) Realm() realm.Realm {
	return i.r
}

// IECClientTestState returns a test state for testing the IEC client
func IECClientTestState(r realm.Realm, iec *things.IEC) TestState {
	return &iecTestState{
		iec: iec,
		r:   r,
	}
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
func CreateIdentity(r realm.Realm, data ThingData) (ThingData, bool) {
	if data.Id.Name == "" {
		data.Id.Name = RandomName()
	}
	if data.Id.Password == "" {
		data.Id.Password = RandomName()
	}
	return data, am.CreateIdentity(r, data.Id) == nil
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
