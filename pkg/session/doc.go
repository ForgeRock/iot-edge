/*
 * Copyright 2020-2023 ForgeRock AS
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

// Package session allows direct access to the SDK session management API.
// Use it to obtain a Single Sign On (SSO) token from Access Management.
//
// This example shows how to use a username and password to authenticate and obtain an SSO token:
//
//	// Connect directly to AM
//	amURL, _ := url.Parse("https://am.example.com:8443/am")
//
//	// Create a session by authenticating with a username and password
//	session, _ := builder.Session().
//	    ConnectTo(amURL).
//	    InRealm("/all-the-things").
//	    WithTree("auth-tree").
//	    AuthenticateWith(
//	        callback.NameHandler{Name: "my-device"},
//	        callback.PasswordHandler{Password: "password"}).
//	    Create()
//
//	// The SSO token can be used to authorize REST requests directly with AM
//	ssoToken := session.Token()
package session
