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

FQDN=
if [ -n "$1" ]; then
  FQDN=$1
  echo "Setting FQDN: $FQDN"
fi

cd things
client_assertion=$(go run ./cmd/jwt-bearer-token --fqdn $FQDN)
echo $client_assertion
cd - &>/dev/null

#curl \
#--request POST "https://$FQDN/am/oauth2/realms/root/access_token" \
#--data "grant_type=client_credentials" \
#--data "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" \
#--data "client_assertion=$client_assertion"

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
                     \"value\": \"${client_assertion}\"
                 }
             ]
         }
     ]}")
ssoToken=$(jq -r '.tokenId' <(echo $authResponse))

tokenResponse=$(curl --silent \
--request POST "https://$FQDN/am/json/things/*?_action=get_access_token" \
--header "Accept-API-Version: protocol=2.0,resource=1.0" \
--header "Content-Type: application/json" \
--header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
--data-raw '{
    "scope":["publish"]
}')
accessToken=$(jq -r '.access_token' <(echo $tokenResponse))

curl --silent --request POST "https://$FQDN/am/json/things/*?_action=introspect_token" \
--header "Accept-API-Version: protocol=2.0,resource=1.0" \
--header "Content-Type: application/json" \
--header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
--data-raw "{
    \"token\":\"$accessToken\"
}" | jq '.'
