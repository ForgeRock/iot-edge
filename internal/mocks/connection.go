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

package mocks

import (
	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/internal/introspect"
	"github.com/dchest/uniuri"
)

// MockClient mocks a client.Connection
type MockClient struct {
	AuthenticateFunc          func(client.AuthenticatePayload) (client.AuthenticatePayload, error)
	AMInfoFunc                func() (client.AMInfoResponse, error)
	AMInfoSet                 client.AMInfoResponse
	AccessTokenFunc           func(string, string) ([]byte, error)
	AttributesFunc            func(string, string, []string) ([]byte, error)
	UserCodeFunc              func(string, string) ([]byte, error)
	UserTokenFunc             func(string, string) ([]byte, error)
	IntrospectAccessTokenFunc func(string, string) ([]byte, error)
}

func (m *MockClient) ValidateSession(tokenID string) (ok bool, err error) {
	return true, nil
}

func (m *MockClient) LogoutSession(tokenID string) (err error) {
	return nil
}

func (m *MockClient) Initialise() error {
	m.AMInfoSet = client.AMInfoResponse{
		AccessTokenURL: "/things",
		ThingsVersion:  "1",
	}
	return nil
}

func (m *MockClient) Authenticate(payload client.AuthenticatePayload) (reply client.AuthenticatePayload, err error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(payload)
	}
	reply.TokenID = uniuri.New()
	return reply, nil
}

func (m *MockClient) AMInfo() (info client.AMInfoResponse, err error) {
	if m.AMInfoFunc != nil {
		return m.AMInfoFunc()
	}
	return m.AMInfoSet, nil
}

func (m *MockClient) AccessToken(tokenID string, _ client.ContentType, payload string) (reply []byte, err error) {
	if m.AccessTokenFunc != nil {
		return m.AccessTokenFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}

func (m *MockClient) IntrospectAccessToken(tokenID string, content client.ContentType, payload string) (introspection []byte, err error) {
	if m.IntrospectAccessTokenFunc != nil {
		return m.IntrospectAccessTokenFunc(tokenID, payload)
	}
	return introspect.InactiveIntrospectionBytes, nil
}

func (m *MockClient) Attributes(tokenID string, _ client.ContentType, payload string, names []string) (reply []byte, err error) {
	if m.AttributesFunc != nil {
		return m.AttributesFunc(tokenID, payload, names)
	}
	return []byte("{}"), nil
}

func (m *MockClient) UserCode(tokenID string, _ client.ContentType, payload string) (reply []byte, err error) {
	if m.UserCodeFunc != nil {
		return m.UserCodeFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}

func (m *MockClient) UserToken(tokenID string, _ client.ContentType, payload string) (reply []byte, err error) {
	if m.UserTokenFunc != nil {
		return m.UserTokenFunc(tokenID, payload)
	}
	return []byte("{}"), nil
}
