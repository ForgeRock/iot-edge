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

package amtest

import (
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

const (
	CookieName         = "iPlanetDirectoryPro"
	SimpleTestRealm    = "testRealm"
	SimpleTestAuthTree = "testTree"
)

// Server mocks the endpoints of AM used by iot edge
type Server struct {
	ServerInfoHandler   http.HandlerFunc
	AuthenticateHandler http.HandlerFunc
}

// NewSimpleServer creates a test server that does the minimum to serve the iot endpoints
func NewSimpleServer() Server {
	return Server{
		ServerInfoHandler: func(writer http.ResponseWriter, request *http.Request) {
			writer.Write([]byte(fmt.Sprintf(`{"cookieName":"%s"}`, CookieName)))
		},
		AuthenticateHandler: func(writer http.ResponseWriter, request *http.Request) {
			// check that the query is correct
			if realm, ok := request.URL.Query()["realm"]; !ok || len(realm) != 1 || realm[0] != SimpleTestRealm {
				http.Error(writer, "incorrect realm query", http.StatusBadRequest)
			}
			if tree, ok := request.URL.Query()["authIndexValue"]; !ok || len(tree) != 1 || tree[0] != SimpleTestAuthTree {
				http.Error(writer, "incorrect auth tree query", http.StatusBadRequest)
			}
			if authType, ok := request.URL.Query()["authIndexType"]; !ok || len(authType) != 1 || authType[0] != "service" {
				http.Error(writer, "incorrect auth type query", http.StatusBadRequest)
			}
			// write a "token"
			writer.Write([]byte(`{"tokenId":"12345"}`))
		},
	}
}

// Start the test server
func (s Server) Start(addr string) *http.Server {
	router := mux.NewRouter()
	router.HandleFunc("/json/serverinfo/*", s.ServerInfoHandler)
	router.HandleFunc("/json/authenticate", s.AuthenticateHandler)
	server := &http.Server{
		Addr:    addr,
		Handler: router,
	}
	go func() {
		server.ListenAndServe()
	}()
	return server
}
