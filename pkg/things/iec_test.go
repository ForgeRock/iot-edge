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
	AuthenticateFunc func(AuthenticatePayload) (AuthenticatePayload, error)
	amInfoFunc       func() (AMInfoSet, error)
	amInfo           AMInfoSet
	sendCommandFunc  func(string, string) ([]byte, error)
}

func (m *mockClient) Initialise() error {
	m.amInfo = AMInfoSet{
		IoTURL:     "/info",
		IoTVersion: "1",
	}
	return nil
}

func (m *mockClient) Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenId = uniuri.New()
	return reply, nil
}

func (m *mockClient) AMInfo() (info AMInfoSet, err error) {
	if m.amInfoFunc != nil {
		return m.amInfoFunc()
	}
	return m.amInfo, nil
}

func (m *mockClient) SendCommand(tokenID string, jws string) (reply []byte, err error) {
	if m.sendCommandFunc != nil {
		return m.sendCommandFunc(tokenID, jws)
	}
	return []byte("{}"), nil
}

func testIEC(client *mockClient) *IEC {
	return &IEC{
		Thing:     Thing{Client: client},
		authCache: tokencache.New(5*time.Minute, 10*time.Minute),
	}

}

// check that the Auth Id Key is not sent to AM
func TestIEC_Authenticate_AuthIdKey_Is_Not_Sent(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(payload AuthenticatePayload) (reply AuthenticatePayload, err error) {
			if payload.AuthIDKey != "" {
				return reply, fmt.Errorf("don't send auth id digest")
			}
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, err := controller.Authenticate(AuthenticatePayload{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = controller.Authenticate(reply)
	if err != nil {
		t.Fatal(err)
	}
}

// check that the Auth Id is not returned by the IEC to the Thing
func TestIEC_Authenticate_AuthId_Is_Not_Returned(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ AuthenticatePayload) (reply AuthenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, _ := controller.Authenticate(AuthenticatePayload{})
	if reply.AuthId != "" {
		t.Fatal("AuthId has been returned")
	}
}

// check that the Auth Id is cached by the IEC
func TestIEC_Authenticate_AuthId_Is_Cached(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ AuthenticatePayload) (reply AuthenticatePayload, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, _ := controller.Authenticate(AuthenticatePayload{})
	id, ok := controller.authCache.Get(reply.AuthIDKey)
	if !ok {
		t.Fatal("The authId has not been stored")
	}
	if id != authId {
		t.Error("The stored authId is not correct")
	}
}
