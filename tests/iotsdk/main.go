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
	"os"

	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
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
	&SendTestCommand{},
}

func runTests() (err error) {
	fmt.Println()
	fmt.Println("====================")
	fmt.Println("-- IoT SDK Tests  --")
	fmt.Println("====================")
	fmt.Println()

	// TODO redirect the debug output to a file
	//anvil.DebugLogger = log.New(os.Stdout, "", 0)
	//things.DebugLogger = anvil.DebugLogger

	// create test realm
	if err := anvil.CreatePrimaryRealm(testdataDir); err != nil {
		return err
	}
	defer func() {
		//_ = anvil.DeletePrimaryRealm()
	}()

	var logfile *os.File
	allPass := true
	for _, test := range tests {
		things.DebugLogger, logfile = anvil.NewFileDebugger(debugDir, anvil.TestName(test))
		if !anvil.RunTest(test) {
			allPass = false
		}
		_ = logfile.Close()
	}
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
