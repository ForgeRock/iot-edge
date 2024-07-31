/*
 * Copyright 2020-2024 ForgeRock AS
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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"github.com/go-jose/go-jose/v3"
)

const (
	execDir     = "."
	testdataDir = execDir + "/testdata/am"
	debugDir    = execDir + "/debug"
	examplesDir = execDir + "/../../examples"
	gatewayDir  = execDir + "/../../cmd/gateway"

	// Auth trees
	jwtAuthWithPoPTree                               = "JWTAuthWithPoP"
	jwtAuthWithPoPWithUnrestrictedTokenTree          = "JWTAuthWithPoPWithUnrestrictedToken"
	jwtAuthWithAssertionTree                         = "JWTAuthWithAssertion"
	jwtAuthWithPoPAndCustomClaimsTree                = "JWTAuthWithPoPAndCustomClaims"
	jwtAuthWithAssertionAndCustomClaimsTree          = "JWTAuthWithAssertionAndCustomClaims"
	jwtRegWithPoPWithCertAndJWTAuthWithPoPTree       = "JWTRegWithPoPWithCertAndJWTAuthWithPoP"
	defaultUnrestrictedTokenTree                     = "JWTRegWithPoPWithCertAndJWTAuthWithPoPWithUnrestrictedToken"
	jwtRegWithPoPWithCertAndJWTAuthWithAssertionTree = "JWTRegWithPoPWithCertAndJWTAuthWithAssertion"
	jwtRegWithSoftStateTree                          = "JWTRegWithSoftState"
	jwtRegWithPoPWithSoftStateTree                   = "JWTRegWithPoPWithSoftState"
	jwtRegWithPoPTree                                = "JWTRegWithPoP"
	jwtRegWithPoPWithCertTree                        = "JWTRegWithPoPWithCert"
	userPwdAuthTree                                  = "AnvilUserPwd"
)

var secretsPath = execDir + "/debug/keys/.secrets"

var iotTests = []anvil.SDKTest{
	&AuthenticateThingJWT{},
	&AuthenticateThingJWTBearer{},
	&AuthenticateThingJWTNonDefaultKID{},
	&AuthenticateWithCustomClaims{},
	&AuthenticateWithCustomClaimsJWTBearer{},
	&RegisterDeviceWithAttributes{},
	&RegisterServiceCert{},
	&AccessTokenWithExactScopes{},
	&AccessTokenWithASubsetOfScopes{},
	&AccessTokenWithUnsupportedScopes{},
	&AccessTokenWithNoScopes{alg: jose.ES256},
	&AccessTokenWithNoScopes{alg: jose.ES384},
	&AccessTokenWithNoScopes{alg: jose.ES512},
	&AccessTokenWithNoScopes{alg: jose.EdDSA},
	&AccessTokenWithNoScopes{alg: jose.PS256},
	&AccessTokenWithNoScopes{alg: jose.PS384},
	&AccessTokenWithNoScopes{alg: jose.PS512},
	&AccessTokenFromCustomClient{},
	&AccessTokenRepeat{},
	&AccessTokenWithExactScopesNonRestricted{},
	&AccessTokenWithNoScopesNonRestricted{},
	&IntrospectAccessToken{restricted: true, tokenType: anvil.ClientSignedTokenType(jose.ES256)},
	&IntrospectAccessToken{restricted: true, tokenType: anvil.ClientSignedTokenType(jose.HS256)},
	&IntrospectAccessToken{restricted: true, tokenType: anvil.CTS},
	&IntrospectAccessToken{restricted: true, tokenType: anvil.ClientEncrypted},
	&IntrospectAccessToken{restricted: false, tokenType: anvil.ClientSignedTokenType(jose.ES256)},
	&IntrospectAccessToken{restricted: false, tokenType: anvil.CTS},
	&IntrospectFakeAccessToken{},
	&IntrospectAccessTokenFromCustomClient{},
	&IntrospectRevokedAccessToken{},
	&AccessTokenExpiredSession{},
	&SimpleThingExample{},
	&SimpleThingExampleTags{limitedTags: false},
	&SimpleThingExampleTags{limitedTags: true},
	&DeviceTokenExample{},
	&GatewayAppAuth{},
	&GatewayAppAuthNonDefaultKID{},
	&AttributesWithNoFilter{},
	&AttributesWithFilter{},
	&AttributesWithNonRestrictedToken{},
	&AttributesExpiredSession{},
	&UnrestrictedSessionTokenAfterAuthentication{},
	&UserTokenAllow{},
	&UserTokenDeny{},
	&UserTokenWithUnsupportedScopes{},
	&UserTokenWithNoScopes{},
	&UserCodeExpiredSession{},
	&UserTokenExpiredSession{},
	&UserTokenRefresh{},
	&UserTokenRefreshWithReducedScope{},
	&UserTokenRefreshWithIncreasedScope{},
	&AccessTokenRefresh{},
	&UnauthorisedAccessTokenRefresh{},
}

var thingsTests = []anvil.SDKTest{
	&AuthenticateWithoutConfirmationKey{},
	&AuthenticateWithIncorrectCustomClaim{},
	&AuthenticateWithUserPwd{},
	&AuthenticateThingThroughGateway{},
	&AuthenticateThingThroughGatewayWithJWTBearer{},
	&AuthenticateWithIncorrectPwd{},
	&RegisterDeviceCert{alg: jose.ES256},
	&RegisterDeviceCert{alg: jose.ES384},
	&RegisterDeviceCert{alg: jose.ES512},
	//&RegisterDeviceCert{alg: jose.EdDSA},
	&RegisterDeviceCert{alg: jose.PS256},
	&RegisterDeviceCert{alg: jose.PS384},
	&RegisterDeviceCert{alg: jose.PS512},
	&RegisterDeviceCertJWTBearer{},
	&RegisterDeviceWithoutCert{},
	&RegisterDeviceNoKeyID{},
	&RegisterDeviceNoKey{},
	&RegisterDeviceSoftState{},
	&RegisterDevicePopAndSoftState{},
	&RegisterDevicePop{},
	&RegisterDevicePopAndCert{},
	&CertRegistrationExample{},
	&PoPRegistrationExample{},
	&PoPSwStmtRegistrationExample{},
	&SwStmtRegistrationExample{},
	&GatewayAppReg{},
	&SessionValid{},
	&SessionInvalid{},
	&SessionLogout{},
	&UnrestrictedSessionTokenAfterRegistration{},
	//&SessionValidWithRestrictedToken{}, // OPENAM-19492
	&SessionLogoutWithRestrictedToken{},
	&AccessTokenAfterDynamicRegistration{},
}

func logFailure(path string, start time.Time, anvilDebug []byte, sdkDebug []byte) {
	err := os.MkdirAll(filepath.Dir(path), 0777)
	if err != nil {
		anvil.ProgressLogger.Println(err)
		return
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0777)
	if err != nil {
	}
	defer func() {
		err = f.Close()
	}()

	// add Anvil logs to logfile
	_, _ = f.WriteString("\n>>>> Anvil Logs <<<<\n")
	_, _ = f.Write(anvilDebug)
	_, _ = f.WriteString("\n")

	// add SDK logs to logfile
	_, _ = f.WriteString("\n>>>> SDK Logs <<<<\n")
	_, _ = f.Write(sdkDebug)
	_, _ = f.WriteString("\n")

	// add AM logs to logfile
	//cmd := exec.Command("docker", "logs", *container, "--since", time.Since(start).String())
	//output, err := cmd.Output()
	//if err == nil {
	//	_, _ = f.WriteString("\n>>>> AM Logs <<<<\n")
	//	_, _ = f.Write(output)
	//	_, _ = f.WriteString("\n")
	//} else {
	//	anvil.ProgressLogger.Println(err)
	//}
}

// run the full test set for a single client
func runAllTestsForContext(testCtx anvil.TestState) (result bool) {
	oldAnvilLogger := am.DebugLogger
	defer func() {
		am.DebugLogger = oldAnvilLogger
	}()

	// put the debug for the client in its own subdirectory
	subDir := filepath.Join(debugDir, fmt.Sprintf("%sClient", testCtx.ClientType()))

	result = true
	var sdkDebug bytes.Buffer
	var anvilDebug bytes.Buffer
	debug.Logger = log.New(&sdkDebug, "", log.Ltime|log.Lmicroseconds|log.Lshortfile)
	anvil.DebugLogger = log.New(&anvilDebug, "", log.Ltime|log.Lmicroseconds|log.Lshortfile)

	allTests := thingsTests
	if !testCtx.EnableOAuth2Things() {
		allTests = append(iotTests, allTests...)
	}
	for _, test := range allTests {
		sdkDebug.Reset()
		anvilDebug.Reset()
		start := time.Now()
		if !anvil.RunTest(testCtx, test) {
			result = false
			logFailure(filepath.Join(subDir, anvil.TestName(test)+".log"), start, anvilDebug.Bytes(), sdkDebug.Bytes())
		}
	}
	return result
}

type realmInfo struct {
	description   string
	name          string
	path          string
	u             *url.URL
	dnsConfigured bool
}

func (i realmInfo) String() string {
	s := i.description
	extra := ""
	if i.dnsConfigured {
		extra = i.u.Hostname()
	} else {
		extra = i.name
	}
	return fmt.Sprintf("%s (%s)", s, extra)
}

func runAllTestsForRealm(realm realmInfo, enableOAuth2Things bool) (result bool, err error) {
	fmt.Printf("\n\n-- Running Tests in %s --\n\n", realm)

	fmt.Printf("-- Running AM Connection Tests --\n\n")

	result = runAllTestsForContext(anvil.NewTestState(nil, realm.u, realm.name, realm.path, realm.dnsConfigured,
		enableOAuth2Things))

	if !enableOAuth2Things {
		fmt.Printf("\n-- Running IoT Gateway COAP Connection Tests --\n\n")

		// run the IoT Gateway
		gateway, err := anvil.TestGateway(realm.u, realm.name, realm.path, jwtAuthWithPoPTree, realm.dnsConfigured)
		if err != nil {
			return false, err
		}
		err = gateway.Initialise()
		if err != nil {
			return false, err
		}
		gatewayKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		err = gateway.StartCOAPServer("127.0.0.1:0", gatewayKey)
		if err != nil {
			return false, err
		}
		defer gateway.ShutdownCOAPServer()

		result = runAllTestsForContext(anvil.NewTestState(gateway, realm.u, realm.name, realm.path, realm.dnsConfigured,
			enableOAuth2Things)) && result
	}
	return result, nil
}

func runAMTests() (err error) {
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

	aliasRealm := anvil.RandomName()
	alias := "alias-" + aliasRealm
	realmId, err := anvil.CreateRealmWithAlias(aliasRealm, alias)
	if err != nil {
		return err
	}
	realmIds = append(realmIds, realmId)

	dnsRealm := anvil.RandomName()
	dnsURL := anvil.URL(dnsRealm)
	realmId, err = anvil.CreateRealmWithDNSAlias(dnsRealm, dnsURL.Hostname())
	if err != nil {
		return err
	}
	realmIds = append(realmIds, realmId)

	defer func() {
		deferError := anvil.DeleteRealms(realmIds)
		if deferError != nil {
			err = deferError
		}
	}()

	realms := []realmInfo{
		{description: "root", name: anvil.RootRealm, path: anvil.RootRealm, u: anvil.BaseURL()},
		{description: "sub-realm", name: subRealm, path: subRealm, u: anvil.BaseURL()},
		{description: "sub-sub-realm", name: subSubRealm, path: subSubRealm, u: anvil.BaseURL()},
		{description: "realm with alias", name: alias, path: anvil.RootRealm + aliasRealm, u: anvil.BaseURL()},
		{description: "realm with DNS alias", name: dnsRealm, path: anvil.RootRealm + dnsRealm, u: dnsURL, dnsConfigured: true},
	}

	// Configure the test realms in a single batch.
	// Gives more time for the realm configuration changes to complete.
	for _, r := range realms {
		err = anvil.ConfigureTestRealm(r.name, testdataDir)
		if err != nil {
			return err
		}
	}
	defer func() {
		// Restore root realm, the others will be deleted
		deferError := anvil.RestoreTestRealm(anvil.RootRealm, testdataDir)
		if deferError != nil {
			err = deferError
		}
	}()

	allPass := true
	for _, r := range realms {
		if err != nil {
			return err
		}
		pass, err := runAllTestsForRealm(r, false)
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

func runPlatformTests() (err error) {
	if *amURL == "" || *amPassword == "" {
		return fmt.Errorf("platform URL and password must be specified")
	}
	u, err := url.Parse(*amURL)
	if err != nil {
		return err
	}
	am.AMURL = *amURL
	am.AdminPassword = *amPassword
	err = anvil.CreateAgentGroup(anvil.RootRealm, testdataDir)
	if err != nil {
		return err
	}
	enableOAuth2Things, err := anvil.IsOAuth2ThingsEnabled(anvil.RootRealm)
	pass, err := runAllTestsForRealm(realmInfo{
		description: "root",
		name:        anvil.RootRealm,
		path:        anvil.RootRealm,
		u:           u,
	}, enableOAuth2Things)
	if err != nil {
		return err
	}
	if !pass {
		return fmt.Errorf("test FAILURE")
	}
	return nil
}

func runTests() (err error) {
	fmt.Println()
	fmt.Println("=====================")
	fmt.Println("-- IoT SDK Tests --")
	fmt.Println("=====================")

	// delete old debug files by removing the debug directory
	err = os.RemoveAll(debugDir)
	if err != nil {
		return err
	}
	// create a temp secrets file
	secretsPath, err = filepath.Abs(secretsPath)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Dir(secretsPath), 0777)
	if err != nil {
		return err
	}

	am.DebugLogger = anvil.ProgressLogger

	if *deployment == "platform" {
		fmt.Printf("\n\n-- Running Platform Tests --\n\n")
		return runPlatformTests()
	}
	if *deployment == "am" {
		fmt.Printf("\n\n-- Running Standalone AM Tests --\n\n")
		return runAMTests()
	}
	return fmt.Errorf("deployment value must be 'am' or 'platform'")
}

var (
	container  = flag.String("container", "am", "The name of the AM container.")
	deployment = flag.String("deployment", "am", "The deployment against which Anvil will run: 'am' or 'platform'.")
	amURL      = flag.String("url", "", "The AM URL of the platform deployment.")
	amPassword = flag.String("password", "", "The AM password for 'amadmin' of the platform deployment.")
)

func main() {
	flag.Parse()
	if err := runTests(); err != nil {
		anvil.ProgressLogger.Fatalf("\n%s %s", anvil.FailString, err)
	}
	anvil.ProgressLogger.Println("\n", anvil.PassString)
	os.Exit(0)
}
