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

package main

import (
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"os"
	"path/filepath"
)

const (
	execDir     = "./tests/iotsdk"
	testdataDir = execDir + "/testdata"
	debugDir    = execDir + "/debug"
)

// define the full test set
var tests = []anvil.SDKTest{
	&AuthenticateWithUsernameAndPassword{},
	&AuthenticateWithoutConfirmationKey{},
	&AccessTokenWithExactScopes{},
	&AccessTokenWithASubsetOfScopes{},
	&AccessTokenWithUnsupportedScopes{},
	&AccessTokenWithNoScopes{},
	&AccessTokenFromCustomClient{},
	&SimpleThingExample{},
}

// run the full test set for a single client
func runAllTestsForClient(client things.Client) (result bool) {
	// put the debug for the client in its own subdirectory
	subDir := filepath.Join(debugDir, anvil.TypeName(client))

	result = true
	var logfile *os.File
	for _, test := range tests {
		things.DebugLogger, logfile = anvil.NewFileDebugger(subDir, anvil.TypeName(test))
		am.DebugLogger = things.DebugLogger
		if !anvil.RunTest(client, test) {
			result = false
		}
		_ = logfile.Close()
	}
	return result
}

func runTests() (err error) {
	fmt.Println()
	fmt.Println("====================")
	fmt.Println("-- IoT SDK Tests  --")
	fmt.Println("====================")
	fmt.Println()

	var logfile *os.File
	am.DebugLogger, logfile = anvil.NewFileDebugger(debugDir, "am-config")
	// create test realm
	if err := anvil.CreatePrimaryRealm(testdataDir); err != nil {
		return err
	}
	defer func() {
		//_ = anvil.DeletePrimaryRealm()
	}()
	_ = logfile.Close()

	allPass := true

	fmt.Printf("-- Running AM Client Tests --\n\n")
	// create AM Client
	amClient := anvil.TestAMClient()
	err = amClient.Initialise()
	if err != nil {
		return err
	}
	allPass = runAllTestsForClient(amClient)

	fmt.Printf("\n-- Running IEC COAP Client Tests --\n\n")

	// run the IEC
	controller := anvil.TestIEC()
	err = controller.Initialise()
	if err != nil {
		return err
	}
	err = controller.StartCOAPServer(anvil.COAPAddress)
	if err != nil {
		return err
	}
	defer controller.ShutdownCOAPServer()

	// create IEC Client
	iecClient := anvil.TestIECClient()
	err = iecClient.Initialise()
	if err != nil {
		return err
	}
	allPass = runAllTestsForClient(iecClient) && allPass

	if !allPass {
		return fmt.Errorf("test FAILURE")
	}
	return nil
}

func main() {
	if err := runTests(); err != nil {
		anvil.DebugLogger.Println("Test failure: ", err)
		anvil.ProgressLogger.Fatal("\nFAIL")
	}
	anvil.ProgressLogger.Println("\nPASS")
	os.Exit(0)
}
