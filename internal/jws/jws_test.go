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

package jws

import (
	"testing"
)

type dummyClaims struct {
	Command string `json:"command"`
}

func TestExtractPayload_Failure(t *testing.T) {
	tests := []struct {
		name     string
		rawToken string
	}{
		{name: "not-compact-serialisation1", rawToken: "12345"},
		{name: "not-compact-serialisation2", rawToken: "12345.67890"},
		{name: "invalid-base64", rawToken: ".AA%."},
		{name: "base64-with-padding", rawToken: ".AA=."},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			claims := dummyClaims{}
			if err := ExtractPayload(subtest.rawToken, &claims); err == nil {
				t.Errorf("expected an error")
			}
		})
	}
}

func TestExtractPayload_Success(t *testing.T) {
	tests := []struct {
		name     string
		rawToken string
		claims   dummyClaims
	}{
		{name: "simple", rawToken: ".eyJjb21tYW5kIjoiZGFuY2UifQ.", claims: dummyClaims{Command: "dance"}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			claims := dummyClaims{}
			if err := ExtractPayload(subtest.rawToken, &claims); err != nil {
				t.Error(err)
			} else if claims != subtest.claims {
				t.Errorf("Expected %s, got %s", subtest.claims, claims)
			}
		})
	}
}
