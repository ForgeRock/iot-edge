/*
 * Copyright 2021 ForgeRock AS
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

import com.sun.identity.idm.AMIdentity
import com.sun.identity.idm.IdUtils
import org.forgerock.json.jose.jwk.JWK
import org.forgerock.json.jose.jwk.JWKSet
import org.forgerock.json.jose.jws.SigningManager
import org.forgerock.oauth2.core.OAuth2Jwt

if (callbacks.isEmpty()) {
    logger.message("No client assertion provided")
    outcome = "Failure"
    return
}

OAuth2Jwt jwt = OAuth2Jwt.create(callbacks.first().getValue())
AMIdentity clientIdentity = IdUtils.getIdentity(jwt.subject, realm, Set.of("uid"))
if (clientIdentity == null || !clientIdentity.exists || !clientIdentity.active) {
    logger.message("Invalid client identity")
    outcome = "Failure"
    return
}

Set<String> keysEntry = clientIdentity.getAttribute("thingKeys")
if (keysEntry.isEmpty()) {
    logger.message("No client keys configured")
    outcome = "Failure"
    return
}

String thingKeys = keysEntry.first()
JWKSet jwkSet = JWKSet.parse(thingKeys)
String kid = jwt.signedJwt.header.keyId
if (kid == null) {
    logger.message("No key ID defined in client assertion")
    outcome = "Failure"
    return
}
JWK verificationKey = jwkSet.findJwk(kid)
if (verificationKey == null) {
    logger.message("No key found in key set")
    outcome = "Failure"
    return
}

if (!jwt.isValid(new SigningManager().newVerificationHandler(verificationKey))) {
    logger.message("Client assertion JWT is not valid")
    outcome = "Failure"
    return
}

sharedState.put("username", jwt.subject)
outcome = "Success"
