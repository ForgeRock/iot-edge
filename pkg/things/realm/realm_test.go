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

package realm

import (
	"fmt"
	"testing"
)

func TestFromString(t *testing.T) {
	sub := SubRealm(Root(), "abcde")
	subSub := SubRealm(sub, "fghij")
	subSubSub := SubRealm(subSub, "klmno")
	tests := []struct {
		name  string
		input string
		realm Realm
	}{
		{name: "root", input: "/", realm: Root()},
		{name: "sub", input: "/abcde", realm: sub},
		{name: "subSub", input: "/abcde/fghij", realm: subSub},
		{name: "subSubSub", input: "/abcde/fghij/klmno", realm: subSubSub},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			result := FromString(subtest.input)
			got := fmt.Sprintf("%#v", result)
			expected := fmt.Sprintf("%#v", subtest.realm)
			if got != expected {
				t.Errorf("expected %s; got %s", expected, got)
			}
		})
	}
}

func TestRoot_URLPath(t *testing.T) {
	sub := SubRealm(Root(), "abcde")
	subSub := SubRealm(sub, "fghij")
	subSubSub := SubRealm(subSub, "klmno")
	tests := []struct {
		name  string
		realm Realm
		path  string
	}{
		{name: "root", realm: Root(), path: "realms/root"},
		{name: "subRealm", realm: sub, path: "realms/root/realms/abcde"},
		{name: "subSubRealm", realm: subSub, path: "realms/root/realms/abcde/realms/fghij"},
		{name: "subSubSubRealm", realm: subSubSub, path: "realms/root/realms/abcde/realms/fghij/realms/klmno"},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if result := subtest.realm.URLPath(); result != subtest.path {
				t.Errorf("expected %s; got %s", subtest.path, result)
			}
		})
	}
}

func TestRealm_Name(t *testing.T) {
	sub := SubRealm(Root(), "abcde")
	subSub := SubRealm(sub, "fghij")
	subSubSub := SubRealm(subSub, "klmno")
	tests := []struct {
		testName string
		realm    Realm
		name     string
	}{
		{testName: "root", realm: Root(), name: "/"},
		{testName: "subRealm", realm: sub, name: "abcde"},
		{testName: "subSubRealm", realm: subSub, name: "fghij"},
		{testName: "subSubSubRealm", realm: subSubSub, name: "klmno"},
	}
	for _, subtest := range tests {
		t.Run(subtest.testName, func(t *testing.T) {
			if result := subtest.realm.Name(); result != subtest.name {
				t.Errorf("expected %s; got %s", subtest.name, result)
			}
		})
	}
}

func TestRealm_ParentPath(t *testing.T) {
	sub := SubRealm(Root(), "abcde")
	subSub := SubRealm(sub, "fghij")
	subSubSub := SubRealm(subSub, "klmno")
	tests := []struct {
		name  string
		realm Realm
		p     string
	}{
		{name: "root", realm: Root(), p: ""},
		{name: "orphanSubRealm", realm: subRealm{parent: nil, name: "orphan"}, p: ""},
		{name: "subRealm", realm: sub, p: "/"},
		{name: "subSubRealm", realm: subSub, p: "/abcde"},
		{name: "subSubSubRealm", realm: subSubSub, p: "/abcde/fghij"},
	}
	for _, subtest := range tests {
		t.Run(subtest.name, func(t *testing.T) {
			if result := subtest.realm.ParentPath(); result != subtest.p {
				t.Errorf("expected %s; got %s", subtest.p, result)
			}
		})
	}
}
