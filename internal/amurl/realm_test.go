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

package amurl

import (
	"testing"
)

func TestNewRealm(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "simple", input: "testRealm", expect: "testRealm"},
		{name: "leading-backslash", input: "/testRealm", expect: "testRealm"},
		{name: "following-backslash", input: "testRealm/", expect: "testRealm"},
		{name: "leading-whitespace", input: " testRealm", expect: "testRealm"},
		{name: "following-whitespace", input: "testRealm\t", expect: "testRealm"},
		{name: "sub-realm", input: "testRealm/subRealm", expect: "testRealm/subRealm"},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			r := string(RealmFromString(subtest.input))
			if r != subtest.expect {
				t.Errorf("Expected %s; got %s", subtest.expect, r)
			}
		})
	}
}

func TestRealm_Path(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "simple", input: "testRealm", expect: "realms/root/realms/testRealm"},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			p := RealmFromString(subtest.input).Path()
			if p != subtest.expect {
				t.Errorf("Expected %s; got %s", subtest.expect, p)
			}
		})
	}
}

func TestRealm_Query(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{name: "simple", input: "testRealm", expect: "testRealm"},
		{name: "sub-realm", input: "testRealm/subRealm", expect: "testRealm/subRealm"},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			p := RealmFromString(subtest.input).Query()
			if p != subtest.expect {
				t.Errorf("Expected %s; got %s", subtest.expect, p)
			}
		})
	}
}
