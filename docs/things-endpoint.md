# Things Endpoint

## Overview

AM provides REST APIs under /json/things for the following use cases:

* [Get the attributes of a Thing](#Get-the-attributes-of-a-Thing)
* [Obtain an OAuth 2.0 Access Token](#Obtain-an-OAuth-2.0-Access-Token)
* [Introspect an OAuth 2.0 Access Token](#Introspect-an-OAuth-2.0-Access-Token)
* [Obtain an OAuth 2.0 User Code](#Obtain-an-OAuth-2.0-User-Code)
* [Obtain an OAuth 2.0 User Token](#Obtain-an-OAuth-2.0-User-Token)
* [Refresh an OAuth 2.0 User Token](#Refresh-an-OAuth-2.0-User-Token)

To use the endpoint, a Thing must be in prosession of a valid session token (SSO Token). How a request to AM is constructed is dependant on the type of SSO token it has received from AM:

* If the Thing has authenticated with a journey that contains the FR IoT Authenticate and/or Register nodes, then its SSO Token is restricted and the request payload to the Things endpoint must be a signed JWT. The JWT must be signed with the same key that was used during the authenication. See [Creating a signed JWT for the Things Endpoint](#creating-a-signed-jwt-for-the-things-endpoint).
* Otherwise, the SSO Token is unrestricted and the request payload to the Things endpoint must be a JSON payload.

## Creating a signed JWT for the Things Endpoint

All calls to the Things Endpoint with a restricted SSO Token must include a signed JWT with the following headers:

| Header Parameter | Value |
| --- | ----------- |
| `aud` | The URL of the request. This must match exactly, including parameters. |
| `api` | The version of the REST API as specified in the request header. |
| `nonce` | An integer value that is greater than any previous value used with this SSO Token specified in the `cookie` header. |

The JWT Claims Set will vary depending on the Things Endpoint action but will match the JSON object used in the non-restricted call.

## Get the attributes of a Thing

To obtain the readable attributes of a Thing, perform an HTTP GET to the `/json/things/*` endpoint, without an action. Use the optional `_fields` parameter to filter the readable attributes. Which attributes that are classed as readable are specified in the [IoT Service](https://backstage.forgerock.com/docs/am/7.1/reference/global-services-configuration.html#global-iot).

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

_None_

### Examples

* [Get Attributes with Restricted SSO Token](#Get-Attributes-with-Restricted-SSO-Token)
* [Get Attributes with Unrestricted SSO Token](#Get-Attributes-with-Unrestricted-SSO-Token)

## Obtain an OAuth 2.0 Access Token

To obtain an OAuth 2.0 Access Token for a Thing, perform an HTTP POST to the `/json/things/*` endpoint, using the `get_access_token` action.

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

Optional array of scopes requested by the Thing. If no scopes are specified then the default scopes of the associated OAuth 2.0 client are returned. If the Thing has no associated OAuth 2.0 client, then the default OAuth 2.0 client as defined in the [IoT Service OAuth 2.0 Client Name](https://ea.forgerock.com/docs/am/reference/global-services-configuration.html#global-iot).

```
{
    "scope":[String]
}
```

### Examples

* [Get Access Token with Restricted SSO Token](#Get-Access-Token-with-Restricted-SSO-Token)
* [Get Access Token with Unrestricted SSO Token](#Get-Access-Token-with-Unrestricted-SSO-Token)


## Introspect an OAuth 2.0 Access Token

To introspect an OAuth 2.0 Access Token for a Thing, perform an HTTP POST to the `/json/things/*` endpoint, using the `introspect_token` action.

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

```
{
    "token":String
}
```

### Examples

* [Introspect Access Token with with Restricted SSO Token](#Introspect-Access-Token-with-Restricted-SSO-Token)
* [Introspect Access Token with Unrestricted SSO Token](#Introspect-Access-Token-with-Unrestricted-SSO-Token)

## Obtain an OAuth 2.0 User Code

To obtain an User Code for the OAuth 2.0 Device Authorization Grant, perform an HTTP POST to the `/json/things/*` endpoint, using the `get_user_code` action.

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

Optional array of scopes requested by the Thing. If no scopes are specified then the default scopes of the associated OAuth 2.0 client are returned. If the Thing has no associated OAuth 2.0 client, then the default OAuth 2.0 client as defined in the [IoT Service OAuth 2.0 Client Name](https://ea.forgerock.com/docs/am/reference/global-services-configuration.html#global-iot).

```
{
    "scope":[String]
}
```

### Examples

* [Get User Code with Restricted SSO Token](#Get-User-Code-with-Restricted-SSO-Token)
* [Get User Code with Unrestricted SSO Token](#Get-User-Code-with-Unrestricted-SSO-Token)

## Obtain an OAuth 2.0 User Token

To obtain an User Token as part of the the OAuth 2.0 Device Authorization Grant, perform an HTTP POST to the `/json/things/*` endpoint, using the `get_user_token` action.

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

```
{
    "device_code":String
}
```

### Examples

* [Get User Token with Restricted SSO Token](#Get-User-Token-with-Restricted-SSO-Token)
* [Get User Token with Unrestricted SSO Token](#Get-User-Token-with-Unrestricted-SSO-Token)

## Refresh an OAuth 2.0 User Token

To obtain an new User Token by exchanging a Refresh Token, perform an HTTP POST to the /json/things/* endpoint, using the `get_access_token` action.

### Request Headers

| Header | Value |
| --- | ----------- |
| `Accept-API-Version` | `resource=2.0, protocol=1.0` |
| `Content-Type` | `application/json` or `application/jose` |
| `cookie` | _sessionCookieName_=_ssoToken_ |

### JSON payload

Required refresh token.

Optional array of scopes requested by the Thing.

```
{
    "refresh_token":String,
    "scope":[String]
}
```

### Examples

* [Get new User Token with Refresh Token with Restricted SSO Token](#Get-new-User-Token-with-Refresh-Token-with-Restricted-SSO-Token)
* [Get new User Token with Refresh Token with Unrestricted SSO Token](#Get-new-User-Token-with-Refresh-Token-with-Unrestricted-SSO-Token)

## Example cURL requests with a Restricted SSO Token

### Setup
```bash
baseURL=https://iot.iam.forgeops.com/am
thingId=bot
tree=RegisterThings
keyfile=./ec_private.pem
```

```bash
# Initiate the authentication request:
authCallback=$(curl \
    --silent \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0' \
    --header 'Content-Type: application/json' \
    --request POST \
    "$baseURL/json/authenticate?authIndexType=service&authIndexValue=$tree")

# Extract challenge:
challenge=$(echo "$authCallback" | \
    jq ".callbacks[0].output[0].value")


# Create the signed authentication JWT:
signedJWT=$(auth-jwt -a "/" -s "$thingId" -kid test -c "$challenge" --key "$keyfile")

# Modify callback:
authCallback=$(echo "$authCallback" | \
    jq ".callbacks[0].input[0].value = \"$signedJWT\"")

# Complete the authentication request:
authResponse=$(curl \
    --silent \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0' \
    --header 'Content-Type: application/json' \
    --request POST \
    --data "$authCallback" \
    "$baseURL/json/authenticate?authIndexType=service&authIndexValue=$tree")

ssoToken=$(jq -r '.tokenId' <(echo $authResponse))
echo "${ssoToken}"
```

### Get Attributes with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?realm=/&_fields=thingConfig" \
    -k "$keyfile" )

attributes=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request GET \
    --data "$jwt" \
    "$baseURL/json/things/*?realm=/&_fields=thingConfig")

echo "$attributes" | jq '.'
```

### Get Access Token with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=get_access_token&realm=/" \
    -k "$keyfile" \
    --custom '{"scope":["profile"]}')

accessTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "$jwt" \
    "$baseURL/json/things/*?_action=get_access_token&realm=/")

accessToken=$(echo "$accessTokenResponse" | jq -r '.access_token')
echo "$accessTokenResponse" | jq '.'
```

### Introspect Access Token with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=introspect_token&realm=/" \
    -k "$keyfile" \
    --custom "{\"token\":\"$accessToken\"}")

introspection=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "$jwt" \
    "$baseURL/json/things/*?_action=introspect_token&realm=/")

echo "$introspection" | jq '.'
```

### Get User Code with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=get_user_code&realm=/" \
    -k "$keyfile" \
    --custom '{"scope":["profile"]}')

userCodeResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "$jwt" \
    "$baseURL/json/things/*?_action=get_user_code&realm=/")

deviceCode=$(echo "$userCodeResponse" | jq -r '.device_code')
echo "$userCodeResponse" | jq -r '.verification_uri_complete'
```

### Get User Token with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=get_user_token&realm=/" \
    -k "$keyfile" \
    --custom "{\"device_code\":\"$deviceCode\"}")


userTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "$jwt" \
    "$baseURL/json/things/*?_action=get_user_token&realm=/")

refreshToken=$(echo "$userTokenResponse" | jq -r '.refresh_token')
echo "$userTokenResponse" | jq '.'
```

### Get new User Token with Refresh Token with Restricted SSO Token

Note: using the `get_access_token` action.
```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=get_access_token&realm=/" \
    -k "$keyfile" \
    --custom "{\"scope\":[\"profile\"],\"refresh_token\":\"$refreshToken\"}")

userTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=${ssoToken}" \
    --request POST \
    --data "$jwt" \
    "${baseURL}/json/things/*?_action=get_access_token&realm=/")

userToken=$(echo "$userTokenResponse" | jq -r '.access_token')
echo "$userTokenResponse" | jq '.'
```

### Introspect a User Token with Refresh Token with Restricted SSO Token

```bash
jwt=$(things-jwt \
    -u "$baseURL/json/things/*?_action=introspect_token&realm=/" \
    -k "$keyfile" \
    --custom "{\"token\":\"$userToken\"}")

introspection=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/jose' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "$jwt" \
    "$baseURL/json/things/*?_action=introspect_token&realm=/")

echo "$introspection" | jq '.'
```
## Example cURL requests with a Unrestricted SSO Token

### Setup

```bash
baseURL=https://iot.iam.forgeops.com/am
thingId=bot
thingPassword=Password1
```

Authenticate

```bash
authResponse=$(curl \
    --silent \
    --header "X-OpenAM-Username: $thingId" \
    --header "X-OpenAM-Password: $thingPassword" \
    --request POST \
    "$baseURL/json/authenticate?realm=/")

ssoToken=$(echo "$authResponse" | jq -r '.tokenId')
echo "$ssoToken"
```

### Get Attributes with Unrestricted SSO Token

```bash
attributes=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request GET \
    "$baseURL/json/things/*?realm=/&_fields=thingConfig")

echo "$attributes" | jq '.'
```

### Get Access Token with Unrestricted SSO Token

```bash
accessTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=${ssoToken}" \
    --request POST \
    --data '{"scope":["profile"]}' \
    "${baseURL}/json/things/*?_action=get_access_token&realm=/")

accessToken=$(echo "$accessTokenResponse" | jq -r '.access_token')
echo "$accessTokenResponse" | jq '.'
```

### Introspect Access Token with Unrestricted SSO Token

```bash
introspection=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "{\"token\":\"$accessToken\"}" \
    "$baseURL/json/things/*?_action=introspect_token&realm=/")

echo "$introspection" | jq '.'
```

### Get User Code with Unrestricted SSO Token

```bash
userCodeResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data '{"scope":["profile"]}' \
    "$baseURL/json/things/*?_action=get_user_code&realm=/")

deviceCode=$(echo "$userCodeResponse" | jq -r '.device_code')
echo "${userCodeResponse}" | jq -r '.verification_uri_complete'
```

### Get User Token with Unrestricted SSO Token

```bash
userTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "{\"device_code\":\"$deviceCode\"}" \
    "$baseURL/json/things/*?_action=get_user_token&realm=/")

refreshToken=$(echo "$userTokenResponse" | jq -r '.refresh_token')
echo "$userTokenResponse" | jq '.'
```

### Get new User Token with Refresh Token with Unrestricted SSO Token

Note: using the `get_access_token` action.

```bash
userTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=${ssoToken}" \
    --request POST \
    --data "{\"scope\":[\"profile\"],\"refresh_token\":\"$refreshToken\"}" \
    "${baseURL}/json/things/*?_action=get_access_token&realm=/")

userToken=$(echo "$userTokenResponse" | jq -r '.access_token')
echo "$userTokenResponse" | jq '.'
```

### Introspect a User Token with Refresh Token with Unrestricted SSO Token

```bash
introspection=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "{\"token\":\"$userToken\"}" \
    "$baseURL/json/things/*?_action=introspect_token&realm=/")

echo "$introspection" | jq '.'