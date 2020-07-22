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
	"errors"
	"fmt"
)

// AccessTokenResponse contains the response received from AM after a successful access token request.
// The response format is specified in https://tools.ietf.org/html/rfc6749#section-4.1.4.
type AccessTokenResponse struct {
	Content map[string]interface{}
}

// AccessToken returns the access token contained in an AccessTokenResponse.
func (a AccessTokenResponse) AccessToken() (string, error) {
	return a.GetString("access_token")
}

// ExpiresIn returns the lifetime in seconds of the access token contained in an AccessTokenResponse.
func (a AccessTokenResponse) ExpiresIn() (float64, error) {
	return a.GetNumber("expires_in")
}

// GetNumber reads a number from the AccessTokenResponse.
func (a AccessTokenResponse) GetNumber(key string) (float64, error) {
	if value, ok := a.Content[key].(float64); ok {
		return value, nil
	}
	return 0, errors.New(fmt.Sprintf("failed to read `%s` from response", key))
}

// GetString reads a string from the AccessTokenResponse.
func (a AccessTokenResponse) GetString(key string) (string, error) {
	if value, ok := a.Content[key].(string); ok {
		return value, nil
	}
	return "", errors.New(fmt.Sprintf("failed to read `%s` from response", key))
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
	Content map[string]interface{}
}

// ID returns the thing's ID contained in an AttributesResponse.
func (a AttributesResponse) ID() (string, error) {
	if value, ok := a.Content["_id"].(string); ok {
		return value, nil
	}
	return "", errors.New("failed to read `_id` from response")
}

// GetFirst reads the first value for the specified attribute from the AttributesResponse.
func (a AttributesResponse) GetFirst(key string) (string, error) {
	values, err := a.Get(key)
	if err != nil || len(values) == 0 {
		return "", err
	}
	return values[0], nil
}

// Get reads all the values for the specified attribute from the AttributesResponse.
func (a AttributesResponse) Get(key string) ([]string, error) {
	values, ok := a.Content[key].([]interface{})
	if !ok {
		return nil, errors.New(fmt.Sprintf("failed to read `%s` from response", key))
	}
	valuesAsStrings := make([]string, len(values))
	for i, v := range values {
		valuesAsStrings[i] = v.(string)
	}
	return valuesAsStrings, nil
}
