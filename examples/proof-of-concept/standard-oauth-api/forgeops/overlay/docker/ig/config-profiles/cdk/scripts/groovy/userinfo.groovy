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

/* (3) OIDC get user info - Authorization header
 * 1. Rebase URI       -> $am_host
 * 2. Get realm        -> $am_realm
 * 3. Set path         -> /am/oauth2/$am_realm/userinfo
 * 4. Set header       -> Host                             $am_host
 * 5. Return response - claims
 */

request.uri.rebase(new URI("$am_protocol://$am_host" as String))
String realm = ''
if ("$am_realm" as String != '/') {
    realm = "/realms$am_realm/" as String
}

request.uri.setPath("/am/oauth2$realm/userinfo" as String)
request.headers.put("Host", "$am_host" as String)
logger.info(request.uri.toString())
logger.info(request.headers.toString())

return next.handle(context, request)
    .then({ response ->
        logger.info(response.status.toString())

        return response
    })
