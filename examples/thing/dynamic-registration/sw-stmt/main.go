/*
 * Copyright 2022-2023 ForgeRock AS
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
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/ForgeRock/iot-edge/examples/thing/dynamic-registration/jwtutil"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/go-jose/go-jose/v3"
)

var (
	urlString = flag.String("url", "http://am.localtest.me:8080/am", "URL of AM or Gateway")
	realm     = flag.String("realm", "/", "AM Realm")
	audience  = flag.String("audience", "/", "JWT audience")
	regTree   = flag.String("reg-tree", "oauth-reg-tree", "Registration tree")
	authTree  = flag.String("auth-tree", "oauth-auth-tree", "Authentication tree")
	iss       = flag.String("iss", "https://soft-pub.example.com", "The software publisher issuer.")
	debug     = flag.Bool("debug", false, "Enable debug output")
)

// softwareStatementRegistration registers and authenticates a Thing with AM, using the Software Statement registration
// method and the Client Assertion authentication method.
func softwareStatementRegistration() (err error) {
	u, err := url.Parse(*urlString)
	if err != nil {
		return err
	}

	thingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	thingKid, _ := thing.JWKThumbprint(thingKey)
	thingJWK := jose.JSONWebKey{
		KeyID:     thingKid,
		Key:       thingKey.Public(),
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	ss, err := jwtutil.SoftwareStatement(*iss, thingJWK, nil)
	if err != nil {
		return err
	}

	deviceBuilder := builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*regTree).
		HandleCallbacksWith(
			callback.SoftwareStatementHandler(ss))

	fmt.Printf("Register thing using Software Statement... ")
	device, err := deviceBuilder.Create()
	if err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Printf("Requesting attributes... ")
	attrs, err := device.RequestAttributes()
	if err != nil {
		return err
	}
	if err = device.Logout(); err != nil {
		return err
	}
	fmt.Println("Done")
	fmt.Println("Attributes: ", attrs)
	thingName, err := attrs.ID()
	if err != nil {
		return err
	}
	deviceBuilder = builder.Thing().
		ConnectTo(u).
		InRealm(*realm).
		WithTree(*authTree).
		AuthenticateThing(thingName, *audience, thingKid, thingKey, nil)
	fmt.Printf("Authenticate thing using Client Assertion... ")
	device, err = deviceBuilder.Create()
	if err != nil {
		return err
	}
	fmt.Println("Done")

	fmt.Printf("Requesting access token... ")
	tokenResponse, err := device.RequestAccessToken("publish")
	if err != nil {
		return err
	}
	fmt.Println("Done")
	token, err := tokenResponse.AccessToken()
	if err != nil {
		return err
	}
	fmt.Println("Access token:", token)
	expiresIn, err := tokenResponse.ExpiresIn()
	if err != nil {
		return err
	}
	fmt.Println("Expires in:", expiresIn)
	scopes, err := tokenResponse.Scope()
	if err != nil {
		return err
	}
	fmt.Println("Scope(s):", scopes)

	if err = device.Logout(); err != nil {
		return err
	}
	return nil
}

func main() {
	flag.Parse()
	// pipe debug to standard out
	if *debug {
		thing.DebugLogger().SetOutput(os.Stdout)
	}

	if err := softwareStatementRegistration(); err != nil {
		fmt.Printf("Fatal error: %s", err)
		os.Exit(1)
	}
}
