/*
 * Copyright 2019-2023 ForgeRock AS
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/aws/aws-lambda-go/lambda"
)

var awsPublishResource string

// IoTCustomAuthorizerRequest contains data coming in to a custom IoT device gateway authorizer function.
type IoTCustomAuthorizerRequest struct {
	AuthorizationToken string `json:"token"`
	Type               string `json:"type"`
	MethodArn          string `json:"methodArn"`
}

// IoTCustomAuthorizerResponse represents the expected format of an IoT device gateway authorization response.
type IoTCustomAuthorizerResponse struct {
	IsAuthenticated bool   `json:"isAuthenticated"`
	PrincipalID     string `json:"principalId"`
	//disconnectAfterInSeconds must be greater than 5 minutes and less than 24 hours
	DisconnectAfterInSeconds int32 `json:"disconnectAfterInSeconds"`
	//refreshAfterInSeconds must be greater than 5 minutes and less than 24 hours
	RefreshAfterInSeconds int32    `json:"refreshAfterInSeconds"`
	PolicyDocuments       []string `json:"policyDocuments"`
}

type IoTPolicyDocument struct {
	Version   string      `json:"Version"`
	Statement []IoTPolicy `json:"Statement"`
}

type IoTPolicy struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

type policyClient struct {
}

type authorizationToken struct {
	AccessToken string `json:"access_token"`
	AmURL       string `json:"am_url"`
}

func (c *policyClient) handleRequest(ctx context.Context, event IoTCustomAuthorizerRequest) (IoTCustomAuthorizerResponse, error) {
	if event.AuthorizationToken == "" {
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	log.Printf("Authorization token: %s\n", event.AuthorizationToken)

	tokenInfo, err := introspect(event.AuthorizationToken)
	if err != nil {
		log.Printf("Introspection error: %v\n", err)
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	active, err := tokenInfo.Active()
	if !active || err != nil {
		log.Printf("Access token is not active")
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	log.Printf("Access token info: %v\n", tokenInfo)

	sub, err := tokenInfo.Content.GetString("sub")
	if err != nil {
		log.Printf("Token info error: %v: %v\n", err, tokenInfo)
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	principleID := strings.ReplaceAll(sub, "-", "")

	scopeString, err := tokenInfo.Content.GetString("scope")
	if err != nil {
		log.Printf("Token info error: %v: %v\n", err, tokenInfo)
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	scope := strings.Split(scopeString, " ")

	policyDocument, err := policyDocument(scope)
	if err != nil {
		log.Printf("Policy document error: %v\n", err)
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}

	response := IoTCustomAuthorizerResponse{
		IsAuthenticated:          true,
		PrincipalID:              principleID,
		DisconnectAfterInSeconds: 24 * 60 * 60,
		RefreshAfterInSeconds:    5 * 60,
		PolicyDocuments:          []string{policyDocument},
	}

	if b, err := json.Marshal(response); err == nil {
		log.Printf("Authorization response: %s\n", string(b))
	} else {
		log.Printf("Authorization error %v\n", err)
	}

	return response, nil
}

func introspect(authorizationTokenJson string) (introspection thing.IntrospectionResponse, err error) {
	var authorizationToken authorizationToken
	err = json.Unmarshal([]byte(authorizationTokenJson), &authorizationToken)
	if err != nil {
		log.Printf("Failed to unmarshal authorization token: %s\n", authorizationTokenJson)
		return
	}
	thingID := "572ddcde-1532-4175-861b-0622ac2f3bf3"
	store := secrets.Store{InMemory: true}
	signer, err := store.Signer(thingID)
	if err != nil {
		log.Fatal(err)
	}
	certificates, err := store.Certificates(thingID)
	if err != nil {
		log.Fatal(err)
	}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, _ := url.Parse(authorizationToken.AmURL)
	service, err := builder.Thing().
		AsService().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(thingID, "/", keyID, signer, nil).
		RegisterThing(certificates, nil).
		Create()
	if err != nil {
		return
	}
	return service.IntrospectAccessToken(authorizationToken.AccessToken)
}

func policyDocument(scopes []string) (string, error) {
	var effect string
	if containsElement(scopes, "publish") {
		effect = "Allow"
	} else {
		effect = "Deny"
	}
	policyDocument, err := json.Marshal(IoTPolicyDocument{
		Version: "2012-10-17",
		Statement: []IoTPolicy{
			{
				Effect:   effect,
				Action:   []string{"iot:publish"},
				Resource: []string{awsPublishResource},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy document: %v", policyDocument)
	}
	return string(policyDocument), nil
}

func containsElement(elems []string, elem string) bool {
	for _, element := range elems {
		if element == elem {
			return true
		}
	}
	return false
}

func main() {
	if value, ok := os.LookupEnv("AWS_PUBLISH_RESOURCE"); ok {
		awsPublishResource = value
	}
	log.Printf("AWS Publish Resource: %s\n", awsPublishResource)

	c := policyClient{}
	lambda.Start(c.handleRequest)
}
