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

package thing

import (
	"testing"

	"github.com/ForgeRock/iot-edge/v7/internal/client"
	"github.com/ForgeRock/iot-edge/v7/internal/mocks"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

func TestDefaultThing_RequestUserToken(t *testing.T) {
	errors := []struct {
		Response string
		Error    client.ResponseError
	}{
		{
			Response: "access_denied",
			Error:    client.ResponseError{ResponseCode: client.CodeForbidden},
		},
		{
			Response: "expired_token",
			Error:    client.ResponseError{ResponseCode: client.CodeForbidden},
		},
		{
			Response: "unknown_error",
			Error:    client.ResponseError{ResponseCode: client.CodeForbidden},
		},
	}
	for _, errorValue := range errors {
		t.Run(errorValue.Response, func(t *testing.T) {
			dt := DefaultThing{
				connection: &mocks.MockClient{
					UserTokenFunc: func(string, string) ([]byte, error) {
						return []byte(`{"detail": {"error": "` + errorValue.Response + `"}}`), errorValue.Error
					},
				},
				handlers: nil,
				session:  &mocks.MockSession{},
			}
			_, err := dt.RequestUserToken(thing.DeviceAuthorizationResponse{})
			if err == nil {
				t.Fatal("Expected error response")
			}
			if errorValue.Response != err.Error() {
				t.Error("Unexpected error response: ", err)
			}
		})
	}
}
