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

package things

import (
	"fmt"
	"github.com/ForgeRock/iot-edge/internal/tokencache"
	"github.com/dchest/uniuri"
	"testing"
	"time"
)

// mockClient mocks a thing.mockClient
type mockClient struct {
	AuthenticateFunc func(authenticatePayload) (authenticatePayload, error)
	amInfoFunc       func() (amInfoSet, error)
	amInfoSet        amInfoSet
	accessTokenFunc  func(string, string) ([]byte, error)
	attributesFunc   func(string, string, []string) ([]byte, error)
}

func (m *mockClient) initialise() error {
	m.amInfoSet = amInfoSet{
		AccessTokenURL: "/things",
		ThingsVersion:  "1",
	}
	return nil
}

func (m *mockClient) authenticate(payload authenticatePayload) (reply authenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenId = uniuri.New()
	return reply, nil
}

func (m *mockClient) amInfo() (info amInfoSet, err error) {
	if m.amInfoFunc != nil {
		return m.amInfoFunc()
	}
	return m.amInfoSet, nil
}

func (m *mockClient) accessToken(tokenID string, _ contentType, payload string) (reply []byte, err error) {
	if m.accessTokenFunc != nil {
		return m.accessTokenFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}

func (m *mockClient) attributes(tokenID string, _ contentType, payload string, names []string) (reply []byte, err error) {
	if m.attributesFunc != nil {
		return m.attributesFunc(tokenID, payload, names)
	}
	return []byte("{}"), nil
}

func testGateway(client *mockClient) *ThingGateway {
	return &ThingGateway{
		Thing:     Thing{Client: client},
		authCache: tokencache.New(5*time.Minute, 10*time.Minute),
	}

}

// check that the Auth Id Key is not sent to AM
func TestGateway_Authenticate_AuthIdKey_Is_Not_Sent(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(payload authenticatePayload) (reply authenticatePayload, err error) {
			if payload.AuthIDKey != "" {
				return reply, fmt.Errorf("don't send auth id digest")
			}
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, err := gateway.authenticate(authenticatePayload{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = gateway.authenticate(reply)
	if err != nil {
		t.Fatal(err)
	}
}

// check that the Auth Id is not returned by the Thing Gateway to the Thing
func TestGateway_Authenticate_AuthId_Is_Not_Returned(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ authenticatePayload) (reply authenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(authenticatePayload{})
	if reply.AuthId != "" {
		t.Fatal("AuthId has been returned")
	}
}

// check that the Auth Id is cached by the Thing Gateway
func TestGateway_Authenticate_AuthId_Is_Cached(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ authenticatePayload) (reply authenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	gateway := testGateway(mockClient)
	reply, _ := gateway.authenticate(authenticatePayload{})
	id, ok := gateway.authCache.Get(reply.AuthIDKey)
	if !ok {
		t.Fatal("The authId has not been stored")
	}
	if id != authId {
		t.Error("The stored authId is not correct")
	}
}
