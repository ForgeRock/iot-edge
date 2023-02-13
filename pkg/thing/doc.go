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

// Package thing provides an SDK for devices and services (things) to interact with the ForgeRock Identity Platform.
// Use it to authenticate and authorize things and access their digital identities.
//
// IoT SDK
//
// The IoT SDK allows things to connect to the ForgeRock Identity Platform either directly or via the IoT Gateway.
// Things can perform tasks like register, authenticate, authorize and interact with their digital identity.
//
// This is an example of using the SDK to register with the platform through Access Management's (AM) authentication
// trees. The platform must be configured with the provided parameters.
//
//   // Initialise keys and certificates
//   var privateKey crypto.Signer = ...
//   keyID, _ := thing.JWKThumbprint(privateKey)
//   var certificate []*x509.Certificate = ...
//
//   // Connect directly to AM
//   amURL, _ := url.Parse("https://am.example.com:8443/am")
//
//   // Create a new thing and register it
//   myDevice, _ := builder.Thing().
//       ConnectTo(amURL).
//       InRealm("/all-the-things").
//       WithTree("reg-auth-tree").
//       AuthenticateThing("my-device", "/all-the-things", keyID, privateKey, nil).
//       RegisterThing(certificate, nil).
//       Create()
//
// Authentication and Registration
//
// AuthenticateThing and RegisterThing provides information for handling callbacks for the ForgeRock
// Authenticate/Register Thing tree nodes. These nodes use the JSON Web Token Proof of Possession (JWT PoP)
// specification (https://tools.ietf.org/html/rfc7800). They require a signed JWT containing Thing credentials
// and claims. Add custom claims to the registration JWT by providing a struct that can be serialized to JSON.
//
//    RegisterThing(certificate, func() interface{} {
//        return struct {
//            SerialNumber string `json:"serial_number"`
//            IPAddress    string `json:"ip_address"`
//        }{
//            SerialNumber: "LeCpmWjXpySAM22sxbUvCgGK",
//            IPAddress:    "127.0.0.1",
//        }
//    })
//
package thing
