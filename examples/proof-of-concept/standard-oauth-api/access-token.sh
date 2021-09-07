#!/usr/bin/env bash
set -e

#
# Copyright 2021 ForgeRock AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

function standardEndpoint() {
  # Standard OAuth 2.0 access token request
  echo $(curl --silent \
  --request POST "https://$FQDN/am/oauth2/realms/root/access_token" \
  --data "grant_type=client_credentials" \
  --data "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" \
  --data "client_assertion=$1" \
  --data "scope=publish fr:idm:*" )
}

function thingsEndpoint() {
  # Request to authenticate the client by verifying the bearer JWT
  authResponse=$(curl --silent \
  --request POST "https://$FQDN/am/json/authenticate?authIndexType=service&authIndexValue=JWTBearerClientAuth" \
  --header "Content-Type: application/json" \
  --header "Accept-API-Version: resource=2.0, protocol=1.0" \
  --data-raw "{
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
                       \"value\": \"$1\"
                   }
               ]
           }
       ]}")
  ssoToken=$(jq -r '.tokenId' <(echo $authResponse))

  # Request the access token via the things endpoint
  echo $(curl --silent \
  --request POST "https://$FQDN/am/json/things/*?_action=get_access_token" \
  --header "Accept-API-Version: protocol=2.0,resource=1.0" \
  --header "Content-Type: application/json" \
  --header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
  --data-raw '{
      "scope":["publish", "subscribe", "fr:idm:*"]
  }')
}

FQDN=
if [ -n "$1" ]; then
  FQDN=$1
  echo "Setting FQDN: $FQDN"
fi

# Register the thing and build the bearer JWT
cd things
client_assertion=$(go run ./cmd/jwt-bearer-token --fqdn $FQDN)
echo $client_assertion
cd - &>/dev/null

#accessToken=$(jq -r '.access_token' <(echo $(standardEndpoint $client_assertion)))
accessToken=$(jq -r '.access_token' <(echo $(thingsEndpoint $client_assertion)))
echo "access token $accessToken"

# NOTE: the following will only work if the things endpoint has been used
# get information about the current session
loginInfo=$(curl --silent --request GET "https://$FQDN/openidm/info/login" \
--header "authorization: Bearer $accessToken")

frId=$(echo ${loginInfo}| jq -r '.authenticationId')
echo "FR Id = $frId"


attributesResponse=$(curl --silent --request GET "https://$FQDN/openidm/managed/thing/$frId?_fields=thingProperties" \
--header "authorization: Bearer $accessToken")
echo "${attributesResponse}"
