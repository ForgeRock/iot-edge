/*
 * Copyright 2022 ForgeRock AS
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

var fr = JavaImporter(
    com.sun.identity.idm.IdUtils,
    org.forgerock.json.jose.jwk.JWKSet,
    org.forgerock.json.jose.jws.SigningManager,
    org.forgerock.oauth2.core.OAuth2Jwt,
    java.util.Set
)


outcome = "Failure"

if (callbacks.isEmpty()) {
    throw Error("No client assertion provided")
}

var jwt = fr.OAuth2Jwt.create(callbacks.get(0).getValue())
var clientIdentity = fr.IdUtils.getIdentity(jwt.subject, realm, fr.Set.of("uid"))
if (clientIdentity == null || !clientIdentity.exists || !clientIdentity.active) {
    throw Error("Invalid client identity")
}

var thingKeys = idRepository.getAttribute(clientIdentity.getName(), "thingKeys").toArray()[0]
if (thingKeys === undefined) {
    throw Error("No client keys configured")
}


var kid = jwt.signedJwt.header.keyId
if (kid == null) {
    throw Error("No key ID defined in client assertion")
}

var jwkSet = fr.JWKSet.parse(thingKeys)
var verificationKey = jwkSet.findJwk(jwt.signedJwt.header.keyId)
if (verificationKey == null) {
    throw Error("No key found in key set")
}

var verifier = new fr.SigningManager().newVerificationHandler(verificationKey)
if (!jwt.isValid(verifier)) {
    throw Error("Client assertion JWT is not valid")
}

sharedState.put("username", jwt.subject)
outcome = "Success"