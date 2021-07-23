Setup:
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

Get access token:
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

Introspect access token
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

Get Attributes
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

Get User Code
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

Get User Token
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

echo "$userTokenResponse" | jq '.'
```

# Unrestricted

Set constants
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

Get access token
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

Introspect access token
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

Get Attributes
```bash
attributes=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request GET \
    "$baseURL/json/things/*?realm=/&_fields=thingConfig")

echo "$attributes" | jq '.'
```

Get User Code
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

Get User Token
```bash
userTokenResponse=$(curl \
    --silent \
    --header 'accept-api-version: protocol=2.0,resource=1.0' \
    --header 'content-type: application/json' \
    --cookie "iPlanetDirectoryPro=$ssoToken" \
    --request POST \
    --data "{\"device_code\":\"$deviceCode\"}" \
    "$baseURL/json/things/*?_action=get_user_token&realm=/")

echo "$userTokenResponse" | jq '.'
```