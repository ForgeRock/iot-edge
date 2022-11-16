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

/* (1) Dynamic Registration
 * /oauth2/register
 * Request 1: (POST) Authenticate using software statement - raw data (JSON)
 * 1.  Set URI         ->  $am_host
 * 2.  Set path        ->  /am/json/authenticate
 * 3.  Set headers     ->  Accept-API-Version      resource=2.0, protocol=1.0
 *                         Content-Type            application/json
 *                         Host                    $am_host
 * 4.  Add params      ->  authIndexType           service
 *                         authIndexValue          oauth-reg-tree
 * 5.  Get software_statement
 * 6.  Transform data
 * 7.  Get response    ->  tokenId
 * Request 2: (GET) Get client ID using SSO token (tokenId)
 * /am/json/things/*
 * 8.  Rebase URI      ->  $am_host
 * 9.  Set path        ->  /am/json/things/*
 * 10. Set headers     ->  Accept-API-Version      protocol=2.0, resource=1.0
 *                         Content-Type            application/json
 *                         Cookie                  iPlanetDirectoryPro=tokenId (step 7)
 *                         Host                    $am_host
 * 11. Get response    ->  _id as clientId
 */

// Part 1 - Authenticate using software statement - tokenId
Request authRequest = new Request()
authRequest.method = 'POST'
authRequest.setUri(new URI("$am_protocol://$am_host" as String))
String realm = ''
if ("$am_realm" as String != '/') {
    realm = "/realms$am_realm" as String
}
authRequest.uri.setPath("/am/json$realm/authenticate" as String)

authRequest.headers.put('Accept-API-Version', 'resource=2.0, protocol=1.0')
authRequest.headers.put('Content-Type', 'application/json')
authRequest.headers.put('Host', "$am_host" as String)

Form params = new Form()
params.add('authIndexType', 'service')
params.add('authIndexValue', 'oauth-reg-tree')
params.appendRequestQuery(authRequest)

Map<String, Object> authRequestMap = request.entity.json as Map<String, Object>
String software_statement = authRequestMap.get('software_statement')

String data = """{
    \"callbacks\": [
        {
            \"type\": \"HiddenValueCallback\",
            \"output\": [
                {
                    \"name\": \"id\",
                    \"value\": \"software_statement\"
                }
            ],
            \"input\": [
                {
                    \"name\": \"IDToken1\",
                    \"value\": \"$software_statement\"
                }
            ]
        }
    ]
}""" as String
authRequest.setEntity(data)

http.send(authRequest)
    .thenAsync({ authResponse ->
        Map<String, Object> authResponseMap = authResponse.entity.json as Map<String, Object>
        String ssoToken = authResponseMap.get('tokenId')

        logger.info('/authenticate oauth-reg-tree response')
        logger.info(authResponse.status.toString())
        logger.info(ssoToken)

        // Part 2 - Get client ID using SSO token - _id
        request.setMethod('GET')
        request.uri.rebase(new URI("$am_protocol://$am_host" as String))
        request.uri.setPath("/am/json$realm/things/*" as String)

        request.headers.put('Accept-API-Version', 'protocol=2.0, resource=1.0')
        request.headers.put('Content-Type', 'application/json')
        request.headers.put('Cookie', "iPlanetDirectoryPro=$ssoToken" as String)
        request.headers.put('Host', "$am_host" as String)

        logger.info(request.uri.toString())
        logger.info(request.headers.toString())
        logger.info(request.entity.json as String)

        return next.handle(context, request)
            .then({ response ->
                logger.info('/things/* response')
                logger.info(response.status.toString())

                Map<String, Object> responseMap = response.entity.json as Map<String, Object>
                responseMap.put('client_id', responseMap.get('_id'))
                responseMap.remove('_id')
                response.setEntity(responseMap)

                return response
            })
    })
