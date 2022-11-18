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

/* (2) Client Credential Grant with JWT Bearer Auth
 * /oauth2/access_token
 * Request 1: (POST) Authenticate using client assertion - x-www-urlencoded form
 * 1.  Set URI         ->  $am_host
 * 2.  Get realm       ->  $am_realm
 * 3.  Set path        ->  /am/json/realms/$am_realm/authenticate
 * 4.  Set headers     ->  Accept-API-Version   resource=2.0, protocol=1.0
 *                         Content-Type         application/json
 *                         Host                 $am_host
 * 5.  Add params      ->  authIndexType        service
 *                         authIndexValue       oauth-auth-tree
 * 6.  Get client_assertion
 * 7.  Transform data
 * 8.  Get response    ->  tokenId
 * Request 2: (POST) Get access token using SSO token (tokenId)
 * 9.  Rebase URI      ->  $am_host
 * 10. Set path        ->  /am/json/realms/$am_realm/things/*
 * 11. Transform data
 * 12. Set headers     ->  Accept-API-Version   protocol=2.0, resource=1.0
 *                         Content-Type         application/json
 *                         Cookie               iPlanetDirectoryPro=tokenId (step 8)
 *                         Host                 $am_host
 * 13. Update params   ->  _action              get_access_token
 * 14. Add data        ->  scope                $scope
 * 15. Get response    ->  access_token
 */

// Part 1 - Authenticate using client assertion (authRequest) - tokenId
Request authRequest = new Request()
authRequest.method = 'POST'
authRequest.setUri(new URI("$am_protocol://$am_host" as String))
String realm = ''
if ("$am_realm" as String != '/') {
    realm = "/realms$am_realm" as String
}
authRequest.uri.setPath("/am/json$realm/authenticate" as String)

authRequest.headers.put('Accept-API-version', 'resource=2.0, protocol=1.0')
authRequest.headers.put('Content-Type', 'application/json')
authRequest.headers.put('Host', "$am_host" as String)

Form params = new Form()
params.add('authIndexType', 'service')
params.add('authIndexValue', 'oauth-auth-tree')
params.appendRequestQuery(authRequest)

String client_assertion = request.entity.form.client_assertion.getAt(0)
String authData = """{
   \"callbacks\": [
       {
           \"type\": \"HiddenValueCallback\",
           \"output\": [
               {
                   \"name\": \"id\",
                   \"value\": \"client_assertion\"
               }
           ],
           \"input\": [
               {
                   \"name\": \"IDToken1\",
                   \"value\": \"$client_assertion\"
               }
           ]
       }
   ]
}""" as String
authRequest.setEntity(authData)

logger.info(authRequest.uri.toString())
logger.info(authRequest.headers.toString())
logger.info(client_assertion)
logger.info(authRequest.entity.json as String)

http.send(authRequest)
    .thenAsync({ authResponse ->
        Map<String, Object> responseMap = authResponse.entity.json as Map<String, Object>
        String ssoToken = responseMap.get('tokenId')

        logger.info('/authenticate oauth-auth-tree response')
        logger.info(authResponse.status.toString())
        logger.info(ssoToken)

        // Part 2 - Get access token using SSO token - access_token
        request.setMethod('POST')
        request.uri.rebase(new URI("$am_protocol://$am_host" as String))
        request.uri.setPath("/am/json$realm/things/*" as String)

        String scope = request.entity.form.scope?.getAt(0)
        request.headers.put('Accept-API-Version', 'protocol=2.0, resource=1.0')
        request.headers.put('Content-Type', 'application/json')
        request.headers.put('Cookie', "iPlanetDirectoryPro=$ssoToken" as String)
        request.headers.put('Host', "$am_host" as String)

        // Refactor scope string into scope list
        String parameter = scope.split(" ")[0]
        String value = scope.split(" ")[1]
        String scopeList = """[\"$parameter\", \"$value\"]""" as String
        String thingsData = """{
          \"scope\": $scopeList
        }""" as String
        request.setEntity(thingsData)

        Form thingsParams = new Form()
        thingsParams.add('_action', 'get_access_token')
        thingsParams.appendRequestQuery(request)

        logger.info(request.uri.toString())
        logger.info(request.headers.toString())
        logger.info(request.entity.json as String)

        return next.handle(context, request)
            .then({ response ->
                logger.info('/things get_access_token response')
                logger.info(response.status.toString())

                return response
            })
    })
