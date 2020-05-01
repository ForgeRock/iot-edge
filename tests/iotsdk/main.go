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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/things"
	"github.com/ForgeRock/iot-edge/pkg/things/realm"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
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
	&AccessTokenWithNoScopes{alg: jose.ES256},
	&AccessTokenWithNoScopes{alg: jose.ES384},
	&AccessTokenWithNoScopes{alg: jose.ES512},
	// ToDo: add support for the following algorithms
	//&AccessTokenWithNoScopes{alg: jose.EdDSA},
	//&AccessTokenWithNoScopes{alg: jose.PS256},
	//&AccessTokenWithNoScopes{alg: jose.PS384},
	//&AccessTokenWithNoScopes{alg: jose.PS512},
	&AccessTokenFromCustomClient{},
	&SimpleThingExample{},
	&SimpleIECExample{},
}

// run the full test set for a single client
func runAllTestsForContext(testCtx anvil.TestContext) (result bool) {
	// put the debug for the client in its own subdirectory
	subDir := filepath.Join(debugDir, anvil.TypeName(testCtx.NewClient()))

	result = true
	var logfile *os.File
	for _, test := range tests {
		things.DebugLogger, logfile = anvil.NewFileDebugger(subDir, anvil.TestName(test))
		am.DebugLogger = things.DebugLogger
		if !anvil.RunTest(testCtx, test) {
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
	// delete old debug files by removing the debug directory
	err = os.RemoveAll(debugDir)
	if err != nil {
		return err
	}
	iotsdkLogger, logfile := anvil.NewFileDebugger(debugDir, "iotsdk")
	am.DebugLogger, things.DebugLogger = iotsdkLogger, iotsdkLogger
	defer func() {
		_ = logfile.Close()
	}()

	//err = anvil.ConfigureTestRealm(realm.Root(), testdataDir)
	//if err != nil {
	//	return err
	//}
	// create test realm
	subRealm, err := anvil.CreateTestRealm(1)
	if err != nil {
		return err
	}

	err = anvil.ConfigureTestRealm(subRealm, testdataDir)
	if err != nil {
		return err
	}
	defer func() {
		//_ = anvil.DeletePrimaryRealm()
	}()

	subSubRealm, err := anvil.CreateTestRealm(2)
	if err != nil {
		return err
	}
	err = anvil.ConfigureTestRealm(subSubRealm, testdataDir)
	if err != nil {
		return err
	}
	defer func() {
		//_ = anvil.DeletePrimaryRealm()
	}()
	allPass := true
	for _, realm := range []realm.Realm{realm.Root(), subRealm, subSubRealm} {

		fmt.Printf("-- Running Tests in realm %s --\n\n", realm)

		fmt.Printf("-- Running AM Client Tests --\n\n")
		allPass = runAllTestsForContext(anvil.AMClientTestContext(realm))

		fmt.Printf("\n-- Running IEC COAP Client Tests --\n\n")

		// run the IEC
		am.DebugLogger, things.DebugLogger = iotsdkLogger, iotsdkLogger
		controller, err := anvil.TestIEC(realm)
		if err != nil {
			return err
		}
		err = controller.Initialise()
		if err != nil {
			return err
		}
		controllerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err = controller.StartCOAPServer(":0", controllerKey)
		if err != nil {
			return err
		}

		allPass = runAllTestsForContext(anvil.IECClientTestContext(realm, controller.Address())) && allPass
		controller.ShutdownCOAPServer()
		//break
	}

	if !allPass {
		return fmt.Errorf("test FAILURE")
	}
	return nil
}

func main() {
	if err := runTests(); err != nil {
		anvil.ProgressLogger.Fatalf("\nFAIL %s", err)
	}
	anvil.ProgressLogger.Println("\nPASS")
	os.Exit(0)
}
