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

	// Auth trees
	jwtPopAuthTree    = "Anvil-JWT-Auth"
	jwtPopRegCertTree = "Anvil-JWT-Reg-Cert"
)

// define the full test set
var tests = []anvil.SDKTest{
	&AuthenticateThingJWT{},
	&AuthenticateThingJWTNonDefaultKID{},
	&AuthenticateWithoutConfirmationKey{},
	&RegisterThingCert{},
	&RegisterThingWithAttributes{},
	&RegisterThingWithoutCert{},
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
	&CertRegistrationExample{},
}

// run the full test set for a single client
func runAllTestsForContext(testCtx anvil.TestState) (result bool) {
	// put the debug for the client in its own subdirectory
	subDir := filepath.Join(debugDir, anvil.TypeName(testCtx.InitClients("")))

	result = true
	var logfile *os.File
	for _, test := range tests {
		things.DebugLogger, logfile = anvil.NewFileDebugger(subDir, anvil.TestName(test))
		if !anvil.RunTest(testCtx, test) {
			result = false
		}
		_ = logfile.Close()
	}
	return result
}

func runAllTestsForRealm(realm string) (result bool, err error) {
	err = anvil.ConfigureTestRealm(realm, testdataDir)
	if err != nil {
		return false, err
	}
	defer func() {
		err = anvil.RestoreTestRealm(realm, testdataDir)
	}()

	fmt.Printf("\n\n-- Running Tests in realm %s --\n\n", realm)

	fmt.Printf("-- Running AM Client Tests --\n\n")
	result = runAllTestsForContext(anvil.AMClientTestState(realm))

	fmt.Printf("\n-- Running IEC COAP Client Tests --\n\n")

	// run the IEC
	controller, err := anvil.TestIEC(realm, jwtPopAuthTree)
	if err != nil {
		return false, err
	}
	err = controller.Initialise()
	if err != nil {
		return false, err
	}
	controllerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = controller.StartCOAPServer(":0", controllerKey)
	if err != nil {
		return false, err
	}
	defer controller.ShutdownCOAPServer()

	result = runAllTestsForContext(anvil.IECClientTestState(realm, controller)) && result
	return result, nil
}

func runTests() (err error) {
	fmt.Println()
	fmt.Println("====================")
	fmt.Println("-- IoT SDK Tests  --")
	fmt.Println("====================")

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

	err = anvil.CreateCertVerificationMapping()
	if err != nil {
		return err
	}

	// create test realms
	subRealm, realmIds, err := anvil.CreateRealmHierarchy(anvil.RandomName())
	if err != nil {
		return err
	}
	randomName := anvil.RandomName()
	subSubRealm, ids, err := anvil.CreateRealmHierarchy(anvil.RandomName(), randomName)
	if err != nil {
		return err
	}
	realmIds = append(realmIds, ids...)
	// Create a doppelganger realm that shares the same name as the subSubRealm but is not IoT configured
	// This checks that the fully qualified realm name is used throughout the SDK
	_, ids, err = anvil.CreateRealmHierarchy(randomName)
	if err != nil {
		return err
	}
	realmIds = append(realmIds, ids...)
	defer func() {
		deferError := anvil.DeleteRealms(realmIds)
		if deferError != nil {
			err = deferError
		}
	}()

	allPass := true
	for _, r := range []string{"/", subRealm, subSubRealm} {
		pass, err := runAllTestsForRealm(r)
		allPass = allPass && pass
		if err != nil {
			return err
		}
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
