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
	"net/url"
	"os"
	"path/filepath"

	"github.com/ForgeRock/iot-edge/v7/internal/debug"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil"
	"github.com/ForgeRock/iot-edge/v7/tests/internal/anvil/am"
	"gopkg.in/square/go-jose.v2"
)

const (
	execDir     = "./tests/thingsdk"
	testdataDir = execDir + "/testdata"
	debugDir    = execDir + "/debug"

	// Auth trees
	jwtPopAuthTree             = "Anvil-JWT-Auth"
	jwtPopAuthTreeCustomClaims = "Anvil-JWT-Auth-Custom-Claims"
	jwtPopRegCertTree          = "Anvil-JWT-Reg-Cert"
	userPwdAuthTree            = "Anvil-User-Pwd"
)

// define the full test set
var tests = []anvil.SDKTest{
	&AuthenticateThingJWT{},
	&AuthenticateThingJWTNonDefaultKID{},
	&AuthenticateWithoutConfirmationKey{},
	&AuthenticateWithCustomClaims{},
	&AuthenticateWithIncorrectCustomClaim{},
	&AuthenticateWithUserPwd{},
	&AuthenticateThingThroughGateway{},
	&AuthenticateWithIncorrectPwd{},
	&RegisterDeviceCert{alg: jose.ES256},
	&RegisterDeviceCert{alg: jose.ES384},
	&RegisterDeviceCert{alg: jose.ES512},
	//&RegisterDeviceCert{alg: jose.EdDSA},
	&RegisterDeviceCert{alg: jose.PS256},
	&RegisterDeviceCert{alg: jose.PS384},
	&RegisterDeviceCert{alg: jose.PS512},
	&RegisterDeviceWithAttributes{},
	&RegisterDeviceWithoutCert{},
	&RegisterServiceCert{},
	&RegisterDeviceNoKeyID{},
	&RegisterDeviceNoKey{},
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
	&IntrospectAccessToken{clientBased: true, alg: jose.ES256},
	&IntrospectAccessToken{clientBased: true, alg: jose.PS256},
	&IntrospectAccessTokenFailure{IntrospectAccessToken{clientBased: false, alg: jose.ES256}},
	&IntrospectAccessTokenFailure{IntrospectAccessToken{clientBased: true, alg: jose.HS256}},
	&IntrospectAccessTokenExpired{IntrospectAccessToken{clientBased: true, alg: jose.ES256}},
	&IntrospectAccessTokenPremature{IntrospectAccessToken{clientBased: true, alg: jose.ES256}},
	&IntrospectFakeAccessToken{},
	&AccessTokenExpiredSession{},
	&SimpleThingExample{},
	&SimpleThingExampleTags{limitedTags: false},
	&SimpleThingExampleTags{limitedTags: true},
	&CertRegistrationExample{},
	&GatewayAppAuth{},
	&GatewayAppAuthNonDefaultKID{},
	&GatewayAppReg{},
	&AttributesWithNoFilter{},
	&AttributesWithFilter{},
	&AttributesWithNonRestrictedToken{},
	&AttributesExpiredSession{},
	&SessionValid{},
	&SessionInvalid{},
	&SessionLogout{},
}

// run the full test set for a single client
func runAllTestsForContext(testCtx anvil.TestState) (result bool) {
	// put the debug for the client in its own subdirectory
	subDir := filepath.Join(debugDir, fmt.Sprintf("%sClient", testCtx.ClientType()))

	result = true
	var logfile *os.File
	for _, test := range tests {
		debug.Logger, logfile = anvil.NewFileDebugger(subDir, anvil.TestName(test))
		if !anvil.RunTest(testCtx, test) {
			result = false
		}
		_ = logfile.Close()
	}
	return result
}

type realmInfo struct {
	description   string
	name          string
	audience      string
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

func runAllTestsForRealm(realm realmInfo) (result bool, err error) {
	err = anvil.ConfigureTestRealm(realm.name, testdataDir)
	if err != nil {
		return false, err
	}
	defer func() {
		err = anvil.RestoreTestRealm(realm.name, testdataDir)
	}()

	fmt.Printf("\n\n-- Running Tests in %s --\n\n", realm)

	fmt.Printf("-- Running AM Connection Tests --\n\n")
	result = runAllTestsForContext(&anvil.AMTestState{
		TestAudience:  realm.audience,
		TestURL:       realm.u,
		Realm:         realm.name,
		DNSConfigured: realm.dnsConfigured,
	})

	fmt.Printf("\n-- Running Thing Gateway COAP Connection Tests --\n\n")

	// run the Thing Gateway
	gateway, err := anvil.TestThingGateway(realm.u, realm.name, realm.audience, jwtPopAuthTree, realm.dnsConfigured)
	if err != nil {
		return false, err
	}
	err = gateway.Initialise()
	if err != nil {
		return false, err
	}
	gatewayKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err = gateway.StartCOAPServer(":0", gatewayKey)
	if err != nil {
		return false, err
	}
	defer gateway.ShutdownCOAPServer()

	result = runAllTestsForContext(
		&anvil.ThingGatewayTestState{
			ThingGateway: gateway,
			Realm:        realm.name,
			TestAudience: realm.audience,
		}) && result

	return result, nil
}

func runTests() (err error) {
	fmt.Println()
	fmt.Println("=====================")
	fmt.Println("-- Thing SDK Tests --")
	fmt.Println("=====================")

	var logfile *os.File
	// delete old debug files by removing the debug directory
	err = os.RemoveAll(debugDir)
	if err != nil {
		return err
	}
	thingsdkLogger, logfile := anvil.NewFileDebugger(debugDir, "thingsdk")
	am.DebugLogger, debug.Logger = thingsdkLogger, thingsdkLogger
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

	allPass := true
	for _, r := range []realmInfo{
		{description: "root", name: anvil.RootRealm, audience: anvil.RootRealm, u: anvil.BaseURL()},
		{description: "sub-realm", name: subRealm, audience: subRealm, u: anvil.BaseURL()},
		{description: "sub-sub-realm", name: subSubRealm, audience: subSubRealm, u: anvil.BaseURL()},
		{description: "realm with alias", name: alias, audience: anvil.RootRealm + aliasRealm, u: anvil.BaseURL()},
		{description: "realm with DNS alias", name: dnsRealm, audience: anvil.RootRealm + dnsRealm, u: dnsURL, dnsConfigured: true},
	} {
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
		anvil.ProgressLogger.Fatalf("\n%s %s", anvil.FailString, err)
	}
	anvil.ProgressLogger.Println("\n", anvil.PassString)
	os.Exit(0)
}
