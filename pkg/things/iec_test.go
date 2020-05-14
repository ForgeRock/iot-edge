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
	"github.com/ForgeRock/iot-edge/pkg/things/payload"
	"github.com/dchest/uniuri"
	"testing"
	"time"
)

// mockClient mocks a thing.mockClient
type mockClient struct {
	AuthenticateFunc    func(payload.Authenticate) (payload.Authenticate, error)
	iotEndpointInfoFunc func() (payload.IoTEndpoint, error)
	iotEndpointInfo     payload.IoTEndpoint
	sendCommandFunc     func(string, string) ([]byte, error)
}

func (m *mockClient) Initialise() error {
	m.iotEndpointInfo = payload.IoTEndpoint{
		URL:     "/info",
		Version: "1",
	}
	return nil
}

func (m *mockClient) Authenticate(payload payload.Authenticate) (reply payload.Authenticate, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenId = uniuri.New()
	return reply, nil
}

func (m *mockClient) IoTEndpointInfo() (info payload.IoTEndpoint, err error) {
	if m.iotEndpointInfoFunc != nil {
		return m.iotEndpointInfoFunc()
	}
	return m.iotEndpointInfo, nil
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
		AuthenticateFunc: func(payload payload.Authenticate) (reply payload.Authenticate, err error) {
			if payload.AuthIDKey != "" {
				return reply, fmt.Errorf("don't send auth id digest")
			}
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, err := controller.Authenticate(payload.Authenticate{})
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
		AuthenticateFunc: func(_ payload.Authenticate) (reply payload.Authenticate, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, _ := controller.Authenticate(payload.Authenticate{})
	if reply.AuthId != "" {
		t.Fatal("AuthId has been returned")
	}
}

// check that the Auth Id is cached by the IEC
func TestIEC_Authenticate_AuthId_Is_Cached(t *testing.T) {
	authId := "12345"
	mockClient := &mockClient{
		AuthenticateFunc: func(_ payload.Authenticate) (reply payload.Authenticate, _ error) {
			reply.AuthId = authId
			return reply, nil

		}}
	controller := testIEC(mockClient)
	reply, _ := controller.Authenticate(payload.Authenticate{})
	id, ok := controller.authCache.Get(reply.AuthIDKey)
	if !ok {
		t.Fatal("The authId has not been stored")
	}
	if id != authId {
		t.Error("The stored authId is not correct")
	}
}
