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
	"strings"
)

// Realm represents a realm in AM
type Realm interface {
	// Name of the realm. Can be used in URL queries.
	Name() string
	// URLPath returns a portion of a URL path that navigates to the realm e.g. "realms/root/realms/iotexample"
	URLPath() string
	// ParentPath returns a string that describes a realm's parents
	ParentPath() string
	fmt.Stringer
}

// splitAndClean splites and cleans a path describing a realm with respect to its ancestors
func splitAndClean(s string) []string {
	parts := strings.Split(s, "/")
	filtered := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// FromString creates a representation of a realm from the string
// The string describes the realm hierarchy in order from the topmost parent realm (the root) to the child realm
// separated by '/'. E.g. /grandparent/parent/child represents `root->grandparent->parent->child
// it is assumed that the top most realm is always the root, usually indicated by a leading '/'
func FromString(s string) (realm Realm) {
	if s == "/" {
		return Root()
	}
	parent := Root()
	for _, part := range splitAndClean(s) {
		realm = SubRealm(parent, part)
		parent = realm
	}
	return realm
}

// Root returns a root realm representation
func Root() Realm {
	return root{}
}

type root struct {
}

func (r root) Name() string {
	return "/"
}

func (r root) String() string {
	return r.Name()
}

func (r root) URLPath() string {
	return "realms/root"
}

func (r root) ParentPath() string {
	return ""
}

// SubRealm returns a representation  of a sub-realm i.e. any realm that is not the root
func SubRealm(parent Realm, name string) Realm {
	return subRealm{
		parent: parent,
		name:   name,
	}
}

type subRealm struct {
	parent Realm
	name   string
}

func (s subRealm) Name() string {
	return s.name
}

func (s subRealm) URLPath() string {
	return s.parent.URLPath() + "/realms/" + s.name
}

func (s subRealm) ParentPath() string {
	switch parent := s.parent.(type) {
	case root:
		return "/"
	case subRealm:
		if parent.parent == Root() {
			return "/" + parent.Name()
		}
		return parent.ParentPath() + "/" + parent.Name()
	}
	return ""
}

func (s subRealm) String() string {
	if s.parent == Root() {
		return "/" + s.Name()
	}
	return s.ParentPath() + "/" + s.Name()
}
