#!/usr/bin/env bash
set -e

#
# Copyright 2021-2022 ForgeRock AS
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

if [[ -z "$AM_URL" ]]; then
  echo "AM_URL must be set prior to running this script"
  exit 1
fi
echo "AM_URL: $AM_URL"

if [[ -z "$IG_URL" ]]; then
  echo "IG_URL must be set prior to running this script"
  exit 1
fi
echo "IG_URL: $IG_URL"

SCOPE_STRING="thingConfig fr:idm:*"
SCOPE_LIST="[\"thingConfig\", \"fr:idm:*\"]"

function oauthRegister() {
  # Standard OAuth 2.0 dynamic client registration request
  echo $(curl --insecure --silent \
  --request POST "$IG_URL/oauth2/register" \
  --header "Content-Type: application/json" \
  --data "{ \"software_statement\": \"$1\"}")
}

function oauthToken() {
  # Standard OAuth 2.0 access token request
  echo $(curl --insecure --silent \
  --request POST "$IG_URL/oauth2/access_token" \
  --data "grant_type=client_credentials" \
  --data "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" \
  --data "client_assertion=$1" \
  --data "scope=$SCOPE_STRING" )
}

function thingsRegister() {
  # Request to register the thing by using a software statement
  regResponse=$(curl --insecure --silent \
  --request POST "$AM_URL/json/authenticate?authIndexType=service&authIndexValue=oauth-reg-tree" \
  --header "Content-Type: application/json" \
  --header "Accept-API-Version: resource=2.0, protocol=1.0" \
  --data-raw "{
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
                       \"value\": \"$1\"
                   }
               ]
           }
       ]}")
  ssoToken=$(jq -r '.tokenId' <(echo $regResponse))

  # Request the things attributes using the SSO token
  echo $(curl --insecure --silent \
  --request GET "$AM_URL/json/things/*" \
  --header "Accept-API-Version: protocol=2.0,resource=1.0" \
  --header "Content-Type: application/json" \
  --header "Cookie: iPlanetDirectoryPro=${ssoToken}")
}

function thingsToken() {
  # Request to authenticate the thing by using a bearer JWT
  authResponse=$(curl --insecure --silent \
  --request POST "$AM_URL/json/authenticate?authIndexType=service&authIndexValue=oauth-auth-tree" \
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
  echo $(curl --insecure --silent \
  --request POST "$AM_URL/json/things/*?_action=get_access_token" \
  --header "Accept-API-Version: protocol=2.0,resource=1.0" \
  --header "Content-Type: application/json" \
  --header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
  --data-raw "{
      \"scope\": $SCOPE_LIST
  }")
}

function runOAuthClientExample() {
  cd things
  software_statement=$(go run ./cmd/software-statement)
  echo "---"
  echo "Software statement:"
  echo $software_statement

  oauthRegisterResponse=$(echo $(oauthRegister $software_statement))
  echo "---"
  echo "OAuth 2.0 Dynamic Registration response:"
  echo $oauthRegisterResponse
  oauthClientID=$(jq -r '.client_id' <(echo $oauthRegisterResponse))

  oauthClientAssertion=$(go run ./cmd/jwt-bearer-token -aud "standard_oauth_aud" -clientID $oauthClientID)
  echo "---"
  echo "OAuth 2.0 client assertion:"
  echo $oauthClientAssertion

  oauthTokenResponse=$(echo $(oauthToken $oauthClientAssertion))
  echo "---"
  echo "OAuth 2.0 Access Token response:"
  echo $oauthTokenResponse

  accessToken=$(jq -r '.access_token' <(echo $oauthTokenResponse))
}

function runThingIdentityExample() {
  cd things
  software_statement=$(go run ./cmd/software-statement)
  echo "---"
  echo "Software statement:"
  echo $software_statement

  thingsRegisterResponse=$(echo $(thingsRegister $software_statement))
  echo "---"
  echo "Things Registration response:"
  echo $thingsRegisterResponse
  thingsClientID=$(jq -r '._id' <(echo $thingsRegisterResponse))

  thingsClientAssertion=$(go run ./cmd/jwt-bearer-token -aud "standard_oauth_aud" -clientID $thingsClientID)
  echo "---"
  echo "Things client assertion:"
  echo $thingsClientAssertion

  thingsTokenResponse=$(echo $(thingsToken $thingsClientAssertion))
  echo "---"
  echo "Things Access Token response:"
  echo $thingsTokenResponse

  accessToken=$(jq -r '.access_token' <(echo $thingsTokenResponse))
}

function requestAttributesWithIDM() {
  # NOTE: the following will only work if the things endpoint has been used
  # get information about the current session
  loginInfo=$(curl --insecure --silent \
    --request GET "https://$FQDN/openidm/info/login" \
    --header "authorization: Bearer $accessToken")
  frId=$(echo ${loginInfo}| jq -r '.authenticationId')
  attributesResponse=$(curl --insecure --silent \
    --request GET "https://$FQDN/openidm/managed/thing/$frId?_fields=thingConfig" \
    --header "authorization: Bearer $accessToken")
  echo "---"
  echo "IDM Thing managed object response:"
  echo "$attributesResponse"
}

# This will only work if an identity is associated with the client
function requestAttributesWithOAuth() {
  attributesResponse=$(curl --insecure --silent \
    --request GET "$IG_URL/oauth2/userinfo" \
    --header "authorization: Bearer $accessToken")
  echo "---"
  echo "OAuth User Info response:"
  echo "$attributesResponse"
}

# Run this to test if the software statement and client assertion works with OAuth 2.0 endpoints
runOAuthClientExample

# Run this to test is the software statement and client assertion works with IoT endpoints
#runThingIdentityExample

# Fetch the identity's attributes in a standard OAuth way
#requestAttributesWithOAuth

# Fetch the identity's attributes in a from IDM
#requestAttributesWithIDM
