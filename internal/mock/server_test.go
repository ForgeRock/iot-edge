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

package mock

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"
)

const testAddress = "127.0.0.1:8008"
const testBaseURL = "http://" + testAddress

func TestSimpleServer_ServerInfo(t *testing.T) {
	server := NewSimpleServer().Start(testAddress)
	defer server.Close()

	response, err := http.Get(testBaseURL + "/json/serverinfo/*")
	if err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := ioutil.ReadAll(response.Body)
	info := struct {
		CookieName string `json:"cookieName"`
	}{}
	err = json.Unmarshal(responseBody, &info)
	if err != nil {
		t.Fatal(err)
	}
	if info.CookieName != CookieName {
		t.Errorf("Cookie Name isn't correct")
	}
}
