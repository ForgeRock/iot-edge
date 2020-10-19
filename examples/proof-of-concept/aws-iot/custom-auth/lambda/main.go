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
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
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
	AccessToken      string `json:"access_token"`
	JWTBearerToken   string `json:"jwt_bearer_token"`
	AuthorizationURL string `json:"authorization_url"`
	ClientID         string `json:"client_id"`
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
	log.Printf("Access token info: %v\n", tokenInfo)

	sub, err := tokenInfoStringEntry(tokenInfo, "sub")
	if err != nil {
		log.Printf("Token info error: %v: %v\n", err, tokenInfo)
		return IoTCustomAuthorizerResponse{}, errors.New("unauthorized")
	}
	principleID := strings.ReplaceAll(sub, "-", "")

	policyDocument, err := policyDocument(tokenInfo)
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

func introspect(authorizationTokenJson string) (map[string]interface{}, error) {
	var authorizationToken authorizationToken
	err := json.Unmarshal([]byte(authorizationTokenJson), &authorizationToken)
	if err != nil {
		log.Printf("Failed to unmarshal authorization token: %s\n", authorizationTokenJson)
		return nil, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	request, err := http.NewRequest(http.MethodPost, authorizationToken.AuthorizationURL, nil)
	if err != nil {
		log.Printf("Failed to create request to: %s\n", authorizationToken.AuthorizationURL)
		return nil, err
	}
	query := request.URL.Query()
	query.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	query.Add("client_assertion", authorizationToken.JWTBearerToken)
	query.Add("client_id", authorizationToken.ClientID)
	query.Add("token", authorizationToken.AccessToken)
	request.URL.RawQuery = query.Encode()

	response, err := client.Do(request)
	if err != nil {
		reqDump, _ := httputil.DumpRequest(request, true)
		log.Printf("Introspection request: %s\n", string(reqDump))
		return nil, err
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		resDump, _ := httputil.DumpResponse(response, true)
		log.Printf("Introspection response: %s\n", string(resDump))
		return nil, err
	}
	log.Printf("Response body:\n%s\n", string(body))

	if response.StatusCode != 200 {
		reqDump, _ := httputil.DumpRequest(request, true)
		resDump, _ := httputil.DumpResponse(response, true)
		log.Printf("Response body:\n%s\n", string(body))
		return nil, fmt.Errorf("invalid introspect status: %s\nRequest:\n%s\nResponse:\n%s", response.Status, reqDump, resDump)
	}

	var tokenInfo map[string]interface{}
	err = json.Unmarshal(body, &tokenInfo)
	if err != nil {
		return nil, err
	}
	return tokenInfo, nil
}

func policyDocument(tokenInfo map[string]interface{}) (string, error) {
	var effect string
	scope, err := tokenInfoStringEntry(tokenInfo, "scope")
	if err != nil {
		return "", err
	}
	scopes := strings.Split(scope, " ")
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

func tokenInfoStringEntry(tokenInfo map[string]interface{}, entry string) (string, error) {
	entryInterface, contains := tokenInfo[entry]
	entryValue, isString := entryInterface.(string)
	if !contains || !isString {
		return "", fmt.Errorf("invalid token info: missing '%s'", entry)
	}
	return entryValue, nil
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
