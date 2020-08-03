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
	"fmt"
	"strings"
)

// JSONContent holds dynamic JSON data
type JSONCContent map[string]interface{}

// GetString returns the string value associated with the key in the JSON object
func (c JSONCContent) GetString(key string) (string, error) {
	if value, ok := c[key].(string); ok {
		return value, nil
	}
	return "", readError{key: key}
}

// GetNumber returns the number value associated with the key in the JSON object
func (c JSONCContent) GetNumber(key string) (float64, error) {
	if value, ok := c[key].(float64); ok {
		return value, nil
	}
	return 0, readError{key: key}
}

// GetBool returns the boolean value associated with the key in the JSON object
func (c JSONCContent) GetBool(key string) (bool, error) {
	if value, ok := c[key].(bool); ok {
		return value, nil
	}
	return false, readError{key: key}
}

// GetStringArray returns all the string values held in the array associated with the key in the JSON object
func (c JSONCContent) GetStringArray(key string) ([]string, error) {
	values, ok := c[key].([]interface{})
	if !ok {
		return nil, readError{key: key}
	}
	valuesAsStrings := make([]string, len(values))
	for i, v := range values {
		valuesAsStrings[i] = v.(string)
	}
	return valuesAsStrings, nil
}

// AccessTokenResponse contains the response received from AM after a successful access token request.
// The response format is specified in https://tools.ietf.org/html/rfc6749#section-4.1.4.
type AccessTokenResponse struct {
	Content JSONCContent
}

// AccessToken returns the access token contained in an AccessTokenResponse.
func (a AccessTokenResponse) AccessToken() (string, error) {
	return a.Content.GetString("access_token")
}

// ExpiresIn returns the lifetime in seconds of the access token contained in an AccessTokenResponse.
func (a AccessTokenResponse) ExpiresIn() (float64, error) {
	return a.Content.GetNumber("expires_in")
}

// Scopes returns the scopes of the access token contained in an AccessTokenResponse.
func (a AccessTokenResponse) Scopes() ([]string, error) {
	scope, err := a.Content.GetString("scope")
	if err != nil {
		return nil, err
	}
	return strings.Split(scope, " "), nil
}

// AttributesResponse contains the response received from AM after a successful request for thing attributes.
// The name of the attribute is the same as the LDAP identity attribute name. The response will contain the thing ID
// and may have multiple values for a single attribute, for example:
//
//    {
//        "_id": "my-device",
//        "foo": ["a", "b", "c"]
//        "bar": ["1"]
//    }
type AttributesResponse struct {
	Content JSONCContent
}

// ID returns the thing's ID contained in an AttributesResponse.
func (a AttributesResponse) ID() (string, error) {
	return a.Content.GetString("_id")
}

// GetFirst reads the first value for the specified attribute from the AttributesResponse.
func (a AttributesResponse) GetFirst(key string) (string, error) {
	values, err := a.Content.GetStringArray(key)
	if err != nil || len(values) == 0 {
		return "", err
	}
	return values[0], nil
}

// IntrospectionResponse contains the introspection of an OAuth 2.0 token.
// The response format is specified in https://tools.ietf.org/html/rfc7662#section-2.2.
type IntrospectionResponse struct {
	Content JSONCContent
}

// Active returns true if the introspection indicates that the presented token is currently active.
func (i IntrospectionResponse) Active() bool {
	active, _ := i.Content.GetBool("active")
	return active
}

type readError struct {
	key string
}

func (e readError) Error() string {
	return fmt.Sprintf("failed to read `%s` from content", e.key)
}
