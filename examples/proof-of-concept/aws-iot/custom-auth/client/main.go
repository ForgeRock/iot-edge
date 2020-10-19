/*
 * Copyright 2019-2020 ForgeRock AS
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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/v7/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/dgrijalva/jwt-go"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

const (
	deviceID                     = "47cf707c-80c1-4816-b067-99db2a443113"
	authorizerName               = "iot-custom-authorizer"
	authorizationTokenHeaderName = "X-Token-Header"
	devicePrivateKeyLocation     = "../keys/device-private.pem"
	message                      = "{\"msg\":\"Hello from client!\"}"
)

var awsPublishURL string

type authorizationToken struct {
	AccessToken string `json:"access_token"`
	AmURL       string `json:"am_url"`
}

func main() {
	amBaseURL := flag.String("am-base-url", "", "Provide the AM base URL")
	awsIoTEndpoint := flag.String("aws-iot-endpoint", "", "Provide the AWS IoT endpoint")
	flag.Parse()

	if *amBaseURL == "" {
		log.Fatal("AM base URL must be provided")
	}
	if *awsIoTEndpoint == "" {
		log.Fatal("AWS IoT endpoint must be provided")
	}
	awsPublishURL = fmt.Sprintf("https://%s/topics/customauthtesting", *awsIoTEndpoint)

	log.Println("Register device with id: ", deviceID)
	signer := secrets.Signer(deviceID)
	certificate := []*x509.Certificate{secrets.Certificate(deviceID, signer.Public())}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, _ := url.Parse(*amBaseURL)
	dynamicThing, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(deviceID, "/", keyID, signer, nil).
		RegisterThing(certificate, nil).
		Create()
	if err != nil {
		log.Fatal("Registration failed", "\nReason: ", err)
	}

	log.Println("Requesting OAuth 2.0 access token:")
	tokenResponse, err := dynamicThing.RequestAccessToken("publish")
	if err != nil {
		log.Fatal("Access token request failed", "\nReason: ", err)
	}
	accessToken, err := tokenResponse.AccessToken()
	if err != nil {
		log.Fatal("Failed to parse access token response", "\nReason: ", err)
	}
	log.Println(accessToken)

	log.Println("Publish message for device:\n", message)
	if err = publishMessage(authorizationTokenJson(accessToken, *amBaseURL)); err != nil {
		log.Fatal("Failed to publish message to AWS: " + err.Error())
	}
}

func authorizationTokenJson(accessToken, amBaseURL string) string {
	token := authorizationToken{
		AccessToken: accessToken,
		AmURL:       amBaseURL,
	}
	tokenJson, err := json.Marshal(token)
	if err != nil {
		log.Fatal("Failed to marshal authorization token: " + err.Error())
	}
	return string(tokenJson)
}

func publishMessage(authorizationToken string) error {

	messageBody := strings.NewReader(message)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	request, err := http.NewRequest(http.MethodPost, awsPublishURL, messageBody)
	if err != nil {
		return err
	}
	request.Header.Set("X-Amz-CustomAuthorizer-Name", authorizerName)
	request.Header.Set("X-Amz-CustomAuthorizer-Signature", tokenSignature(authorizationToken))
	request.Header.Set(authorizationTokenHeaderName, authorizationToken)

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode != 200 {
		reqDump, _ := httputil.DumpRequest(request, true)
		resDump, _ := httputil.DumpResponse(response, true)
		return fmt.Errorf("invalid publish status:  %s\n\nRequest:\n%s\n\nResponse:\n%s\n",
			response.Status, string(reqDump), string(resDump))
	}
	return nil
}

func tokenSignature(token string) string {
	h := crypto.SHA256.New()
	h.Write([]byte(token))
	digest := h.Sum(nil)

	signedBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey(), crypto.SHA256, digest)
	if err != nil {
		log.Fatal("Failed to create signature for token: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(signedBytes)
}

func privateKey() *rsa.PrivateKey {
	keyData, err := ioutil.ReadFile(devicePrivateKeyLocation)
	if err != nil {
		log.Fatal("Failed to read private key: " + err.Error())
	}
	pk, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatal("Failed to parse private key: " + err.Error())
	}
	return pk
}
