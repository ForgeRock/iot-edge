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
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

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

// BaseURL returns the base URL for the test AM
func BaseURL() string {
	return am.AMURL
}

// SDKTest defines the interface required by a SDK API test
type SDKTest interface {
	Setup() bool // setup actions before the test starts
	Run() bool   // function that runs and validates the test
	Cleanup()    // cleanup actions after the test has finished
}

// NopSetupCleanup defines a struct with no-op Setup and Cleanup methods
type NopSetupCleanup struct {
}

// Setup is a no op function
func (t NopSetupCleanup) Setup() bool {
	return true
}

// Cleanup is a no op function
func (t NopSetupCleanup) Cleanup() {
}

// represents the minimum amount of setup to create an identity for use in a test
type BaseSDKTest struct {
	Realm  string
	Id     am.IdAttributes
	Signer crypto.Signer
}

// Setup the base test
// uses sensible defaults for certain fields if none have been set
func (t *BaseSDKTest) Setup() bool {
	if t.Id.Name == "" {
		t.Id.Name = RandomName()
	}
	if t.Id.Password == "" {
		t.Id.Password = RandomName()
	}
	if t.Realm == "" {
		t.Realm = PrimaryRealm()
	}
	err := am.CreateIdentity(t.Realm, t.Id)
	return err == nil
}

// Cleanup the base test
func (t *BaseSDKTest) Cleanup() {
	//_ = am.DeleteIdentity(t.Realm, t.Id.Name)
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

// TestName creates a test name based on the name of the type used to define the test
func TestName(t interface{}) string {
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
	DebugLogger = log.New(file, "", log.Ltime|log.Lshortfile)
	return DebugLogger, file
}

// RunTest runs the given SDKTest
func RunTest(t SDKTest) (pass bool) {
	name := TestName(t)
	ProgressLogger.Printf("%-10s%s\n", runStr, name)
	start := time.Now()
	defer func() {
		ProgressLogger.Print(resultSprint(pass, name, start))
	}()
	if pass = t.Setup(); !pass {
		return
	}
	DebugLogger.Println("*** STARTING TEST RUN")
	pass = t.Run()
	DebugLogger.Printf("*** RUN RESULT: %v", pass)
	t.Cleanup()
	return
}
