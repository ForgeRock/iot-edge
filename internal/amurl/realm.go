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
	"fmt"
	"strings"
)

// Realm represents a realm in AM
type Realm string

// RealmFromString creates a Realm from a string
func RealmFromString(s string) Realm {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "/")
	return Realm(s)
}

// Path returns the URL realm path
func (r Realm) Path() string {
	return fmt.Sprintf("realms/root/realms/%s", string(r))
}

// Query returns the value to select the realm in an URL query
func (r Realm) Query() string {
	return string(r)
}
