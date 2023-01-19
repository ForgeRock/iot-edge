/*
 * Copyright 2021-2023 ForgeRock AS
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

outcome = "False"

// This script should decide if the authenticating thing's certificate should be rotated or not.
// The certificate may need to be rotated when it has expired, revoked or manual rotation was requested.
// This example shows how manual rotation can be achieved. Certificate expiration and revocation should be
// managed as instructed by the issuing certificate authority.

def certificateAttr = idRepository.getAttribute(nodeState.get("_id").asString(), "thingCertificatePem")
def certificateExists = !certificateAttr.isEmpty()
def rotateAttr = idRepository.getAttribute(nodeState.get("_id").asString(), "thingCertificateRotate")
def rotateRequired = false

// Read rotation attribute if it exists
if (!rotateAttr.isEmpty()) {
    def rotate = rotateAttr.iterator().next()
    rotateRequired = Boolean.parseBoolean(rotate.toString())
}

if (!certificateExists || rotateRequired) {
    outcome = "True"
}
