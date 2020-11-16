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
	"github.com/ForgeRock/iot-edge/v7/internal/mocks"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"testing"
)

func TestDefaultThing_RequestUserToken(t *testing.T) {
	errors := []string{
		"access_denied",
		"expired_token",
		"unknown_error",
	}
	for _, errorValue := range errors {
		t.Run(errorValue, func(t *testing.T) {
			dt := DefaultThing{
				connection: &mocks.MockClient{
					UserTokenFunc: func(string, string) ([]byte, error) {
						return []byte("{\"error\": \"" + errorValue + "\"}"), nil
					},
				},
				handlers: nil,
				session:  &mocks.MockSession{},
			}
			_, err := dt.RequestUserToken(thing.DeviceAuthorizationResponse{})
			if err == nil {
				t.Fatal("Expected error response")
			}
			if errorValue != err.Error() {
				t.Error("Unexpected error response: ", err)
			}
		})
	}
}
