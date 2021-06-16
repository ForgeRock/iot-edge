# Authenticate and Authorize without using the IoT SDK

The ForgeRock Identity Platform can be configured to authenticate and authorize things without human interaction.
This can be done via the IoT SDK or by using the `authenticate` and `things` endpoints direct. This example will show
how to use the endpoints directly when the platform is configured for JWT Proof of Possession based authentication.

<img src="docs/no-sdk.png" alt="No SDK flow" width="700"/>

In this scenario a thing is manually registered. It then uses the `authenticate` endpoint to retrieve a session token.
The session token is then used to request an access token from the `things` endpoint.

The authentication journey has been configured with the `AuthenticateThing` node, which requires the thing to
authenticate using a signed JWT containing a challenge sent during the authentication request. On successful
authentication the `AuthenticateThing` node will produce a session token containing a Proof of Possession restriction,
which requires any request to the platform accompanied by the session token to be signed by the thing. In this example
the restriction has been removed to simplify the steps in making the access token request. However, this restriction
should not be removed in a production environment as it strengthens the security of the solution.

### Run the ForgeRock Platform

Install the third party software by following the instructions in the
[ForgeOps docs](https://backstage.forgerock.com/docs/forgeops/7.1/cdk/minikube/setup/sw.html).
Additionally, install [mkcert](https://github.com/FiloSottile/mkcert) for making locally-trusted development certificates.

Clone this repo:
```
git clone https://github.com/ForgeRock/iot-edge.git
cd iot-edge/examples/proof-of-concept/no-sdk
```

Start the platform:
```
./run.sh
```

In a new terminal, run `minikube ip` and map the output from the command to `iot.iam.example.com` in your hosts file:
```
echo "$(minikube ip) iot.iam.example.com" >> /etc/hosts
```

The connection details for the platform will be printed to the console:
```
=====================================================
URL: https://iot.iam.example.com/platform
Username: amadmin
Password: 6KZjOxJU1xHGWHI0hrQT24Fn
DS Password: zMO2W9IlOronDqrF2MtEha3Jiic3urZM
=====================================================
```

### Run example client
The client example will demonstrate how to manually register a thing before authenticating and requesting an access
token.

We will use the authentication tool to generate a key for the thing and to create the signed JWT for authentication.

Build the `auth-tool`:
```bash
go build -o ./bin/auth-tool ./cmd/auth-tool
```

Generate a key for the thing:
```bash
publicKey=$(./bin/auth-tool -key)
keyId=$(jq -r '.keys[0].kid' <(echo $publicKey))
echo $publicKey
```

Manually register the thing identity via the platform UI:
1. Open the [Thing List](https://iot.iam.example.com/platform/?realm=root#/managed-identities/managed/thing).
1. Click the `New Thing` button.
1. Enter the following values in the pop up window:
    * ID: `my-device`
    * Type: `device`
1. Click `Save` to create the thing identity.
1. An entry for `my-device` will appear in the `Thing List`, click on the entry.
1. Copy the generated public key into the `Keys` field and click `Save`.

Initiate the authentication request:
```bash
authCallback=$(curl --request POST 'https://iot.iam.example.com/am/json/authenticate?authIndexType=service&authIndexValue=AuthenticateThings' \
    --header 'Content-Type: application/json' \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0')
authId=$(jq -r '.authId' <(echo $authCallback))
challenge=$(jq -r '(.callbacks[0].output[] | select(.name == "value")).value' <(echo $authCallback))
thingId=my-device
```

Create the signed authentication JWT:
```bash
signedJWT=$(./bin/auth-tool -jwt -sub $thingId -kid $keyId -challenge $challenge)
```

Complete the authentication request:
```bash
authResponse=$(curl --request POST 'https://iot.iam.example.com/am/json/authenticate?authIndexType=service&authIndexValue=AuthenticateThings' \
--header 'Content-Type: application/json' \
--header 'Accept-API-Version: resource=2.0, protocol=1.0' \
--data-raw "{
     \"authId\": \"${authId}\",
     \"callbacks\": [
         {
             \"type\": \"HiddenValueCallback\",
             \"output\": [
                 {
                     \"name\": \"id\",
                     \"value\": \"jwt-pop-authentication\"
                 }
             ],
             \"input\": [
                 {
                     \"name\": \"IDToken1\",
                     \"value\": \"${signedJWT}\"
                 }
             ]
         }
     ]}")
ssoToken=$(jq -r '.tokenId' <(echo $authResponse))
```

Request the access token:
```bash
tokenResponse=$(curl --request POST 'https://iot.iam.example.com/am/json/things/*?_action=get_access_token' \
    --header 'Accept-API-Version: protocol=2.0,resource=1.0' \
    --header 'Content-Type: application/json' \
    --header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
    --data-raw '{
        "scope":["publish"]
    }')
accessToken=$(jq -r '.access_token' <(echo $tokenResponse))
echo $tokenResponse | jq '.'
```

The `things` endpoint will respond with a standard OAuth 2.0 Access Token Response:
```
{
    "access_token":"1b7JX5BYt7OkBIxEBy0gavzX7aA",
    "refresh_token":"5rI_8TxznBppLWBkCOsboUNBW08",
    "scope":"publish",
    "token_type":"Bearer",
    "expires_in":3599
}
```

We can also use the `thing` endpoint to introspect the access token:
```bash
curl --request POST 'https://iot.iam.example.com/am/json/things/*?_action=introspect_token' \
    --header 'Accept-API-Version: protocol=2.0,resource=1.0' \
    --header 'Content-Type: application/json' \
    --header "Cookie: iPlanetDirectoryPro=${ssoToken}" \
    --data-raw "{
        \"token\":\"$accessToken\"
    }" | jq '.'
```