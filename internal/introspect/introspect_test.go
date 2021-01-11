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

package introspect

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/clock"
)

func dummyClaims(nbf, exp int64) []byte {
	b, _ := json.Marshal(timeClaims{
		Exp: exp,
		Nbf: nbf,
	})
	return b
}

func TestValidNow(t *testing.T) {
	now := time.Now()
	clock.Clock = func() time.Time {
		return now
	}
	defer func() {
		clock.Clock = clock.DefaultClock()
	}()

	tests := []struct {
		name     string
		claims   []byte
		expected bool
	}{
		{name: "Invalid", claims: []byte("12345"), expected: false},
		{name: "Within", claims: dummyClaims(now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix()), expected: true},
		{name: "TooEarly", claims: dummyClaims(now.Unix()+Skew+1, now.Add(time.Hour).Unix()), expected: false},
		{name: "TooLate", claims: dummyClaims(now.Add(-time.Hour).Unix(), now.Unix()-Skew), expected: false},
		{name: "WithinNbfSkew", claims: dummyClaims(now.Unix()+Skew/2+1, now.Add(time.Hour).Unix()), expected: true},
		{name: "WithinExpSkew", claims: dummyClaims(now.Add(-time.Hour).Unix(), now.Unix()-Skew/2), expected: true},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			actual := ValidNow(subtest.claims)
			if subtest.expected != actual {
				t.Errorf("expected: %v, actual %v", subtest.expected, actual)
			}
		})
	}
}

func TestCreateFromJWT(t *testing.T) {
	tests := []struct {
		name          string
		claims        []byte
		introspection map[string]interface{}
	}{
		{name: "no-scopes", claims: []byte(`{}`),
			introspection: map[string]interface{}{"active": true}},
		{name: "single-scope", claims: []byte(`{"scope":["one"]}`),
			introspection: map[string]interface{}{"active": true, "scope": "one"}},
		{name: "multiple-scopes", claims: []byte(`{"scope":["one","two"]}`),
			introspection: map[string]interface{}{"active": true, "scope": "one two"}},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			b, err := CreateFromJWT(subtest.claims)
			if err != nil {
				t.Fatal(err)
			}
			var introspection map[string]interface{}
			err = json.Unmarshal(b, &introspection)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(introspection, subtest.introspection) {
				t.Errorf("expected %v; got %v", subtest.introspection, introspection)
			}
		})
	}
}
