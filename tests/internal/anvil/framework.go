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
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/iec"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/ForgeRock/iot-edge/pkg/things"

	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/trees"
	"github.com/dchest/uniuri"
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

// primaryRealm represents the primary test realm
var primaryRealm = struct {
	name string
	id   string
}{}

// CreatePrimaryRealm creates the primary realm and loads all the data in the testDataDir
func CreatePrimaryRealm(testDataDir string) (err error) {
	primaryRealm.name = RandomName()
	primaryRealm.id, err = am.CreateRealm(primaryRealm.name)
	if err != nil {
		return err
	}

	// add tree nodes
	nodes, err := trees.ReadNodes(filepath.Join(testDataDir, "nodes"))
	if err != nil {
		return err
	}
	for _, node := range nodes {
		err = am.CreateTreeNode(PrimaryRealm(), node)
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
		err = am.CreateTree(PrimaryRealm(), tree)
		if err != nil {
			return err
		}
	}

	return nil
}

// DeletePrimaryRealm deletes the primary testing realm
func DeletePrimaryRealm() (err error) {
	return am.DeleteRealm(primaryRealm.id)
}

// PrimaryRealm returns the name of the primary testing realm
func PrimaryRealm() string {
	return primaryRealm.name
}

// TestAMClient creates an AM client that connects with the test AM instance
func TestAMClient() *things.AMClient {
	t := things.NewAMClient(am.AMURL, primaryRealm.name)
	t.Timeout = StdTimeOut
	return t
}

// COAPAddress is the address served by the COAP server run by the test IEC
const COAPAddress = "127.0.0.1:5688"

// TestCOAPClient creates an COAP client that connects with the test IEC instance
func TestCOAPClient() *things.COAPClient {
	c := things.NewCOAPClient(COAPAddress)
	c.Timeout = StdTimeOut
	return c
}

// TestIEC creates a test IEC
func TestIEC() *iec.IEC {
	c := iec.NewIEC(am.AMURL, PrimaryRealm())
	return c
}

// ThingData holds information about a Thing used in a test
type ThingData struct {
	Realm  string
	Id     am.IdAttributes
	Signer crypto.Signer
}

// SDKTest defines the interface required by a SDK API test
type SDKTest interface {
	Setup() (data ThingData, ok bool)              // setup actions before the test starts
	Run(client things.Client, data ThingData) bool // function that runs and validates the test
	Cleanup(data ThingData)                        // cleanup actions after the test has finished
}

// NopSetupCleanup defines a struct with no-op Setup and Cleanup methods
type NopSetupCleanup struct {
}

// Setup is a no op function
func (t NopSetupCleanup) Setup() bool {
	return true
}

// Cleanup is a no op function
func (t NopSetupCleanup) Cleanup(ThingData) {
}

// Create an identity in AM from the supplied data
// uses sensible defaults for certain fields if none have been set
func CreateIdentity(data ThingData) (ThingData, bool) {
	if data.Id.Name == "" {
		data.Id.Name = RandomName()
	}
	if data.Id.Password == "" {
		data.Id.Password = RandomName()
	}
	if data.Realm == "" {
		data.Realm = PrimaryRealm()
	}
	return data, am.CreateIdentity(data.Realm, data.Id) == nil
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

// NewFileDebugger creates a new Anvil logger that logs to file with the given test name
func NewFileDebugger(directory, testName string) (*log.Logger, *os.File) {
	err := os.MkdirAll(directory, 0777)
	if err != nil {
		log.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, testName+".log"))
	if err != nil {
		log.Fatal(err)
	}
	DebugLogger = log.New(file, "", log.Ltime|log.Lmicroseconds|log.Lshortfile)
	return DebugLogger, file
}

// RunTest runs the given SDKTest
func RunTest(client things.Client, t SDKTest) (pass bool) {
	name := TypeName(t)
	ProgressLogger.Printf("%-10s%s\n", runStr, name)
	start := time.Now()
	defer func() {
		ProgressLogger.Print(resultSprint(pass, name, start))
	}()
	var data ThingData
	if data, pass = t.Setup(); !pass {
		return false
	}
	DebugLogger.Println("*** STARTING TEST RUN")
	pass = t.Run(client, data)
	DebugLogger.Printf("*** RUN RESULT: %v", pass)
	t.Cleanup(data)
	return
}
