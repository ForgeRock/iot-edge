# IoT Authentication Nodes

## Overview

Out of the box, AM provides the following nodes for IoT Things:

* [Authenticate Thing Node](#Authenticate-Thing-Node)
* [Register Thing Node](#Register-Thing-Node)

## Authenticate Thing Node

The [node](https://backstage.forgerock.com/docs/am/7.1/authentication-guide/auth-node-configuration-hints.html#auth-node-authenticate-thing)
authenticates a Thing using JWT proof-of-possession.

To use this node, a Thing must:

* Be registered with AM.
* Have an unsymmetric key pair with the public part known to AM.

### IoT Authentication Node Callback

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array containing two objects:

* An `id` object containing the value `jwt-pop-authentication`.  
* A `value` object that holds a challenge from AM. 

For example: 

```
{
    "authId":"eyJ0eXAi...vECYt1J8",
    "callbacks":
        [
            {
                "type":"HiddenValueCallback",
                "output":
                    [
                        {
                            "name":"value",
                            "value":"21Y8UwDVv_A_gKChI-mbRw"
                        },
                        {
                            "name":"id",
                            "value":"jwt-pop-authentication"
                        }
                    ],
                "input":
                    [
                        {
                            "name":"IDToken1",
                            "value":"jwt-pop-authentication"
                        }
                    ]
            }
        ]
}
```

The Thing must create a signed JWT place it in the `IDToken1` object in the `input` array.

### Creating a signed JWT for the IoT Authentication Node

Required Standard Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, usually the Thing ID |
| `aud` | Audience, usually the AM Realm |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |

Required Custom Claims:

| Claim | Value |
| --- | ----------- |
| `nonce` | The challenge from AM |
| `cnf.kid` | Key ID of a public key known to AM |

```
{
    "nonce":String
    "cnf":{
        "kid":String
    }
}
```

Additional custom claims may be added to the JWT and these values will added to the shared state of the Authentication Tree and used for additional authentication if required.

## Register Thing Node

The [node](https://backstage.forgerock.com/docs/am/7.1/authentication-guide/auth-node-configuration-hints.html#auth-node-register-thing)
registers a Thing using JWT proof-of-possession.

To use this node, a Thing must:

* Have a unsymmetric key pair.
* Have a certificate that has been signed by a Certificate Authority known to AM.

### IoT Register Node Callback

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array containing two objects:

* An `id` object containing the value `jwt-pop-registration`.  
* A `value` object that holds a challenge from AM. 

```
{
    "authId":"eyJ0eXAi...B0FUEAn8",
    "callbacks":
        [
            {
                "type":"HiddenValueCallback",
                "output":
                    [
                        {
                            "name":"value",
                            "value":"50EvIp2JbBDqZZlLe_Nzcg"
                        },
                        {
                            "name":"id",
                            "value":"jwt-pop-registration"
                        }
                    ],
                "input":
                    [
                        {
                            "name":"IDToken1","value":"jwt-pop-registration"
                        }
                    ]
            }
        ]
}
```

The Thing must create a signed JWT place it in the `IDToken1` object in the `input` array.

### Creating a signed JWT for the IoT Registration Node

Required Standard Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, usually the Thing ID |
| `aud` | Audience, usually the AM Realm |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |

Required Custom Claims:

| Claim | Value |
| --- | ----------- |
| `nonce` | The challenge from AM |
| `thingType` | Thing Type, either `device`, `service` or `gateway` |
| `cnf.jwk` | Public key and certificate of the device in JSON Web Key form, see [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517)|


```
{
    "nonce":String
    "thingType":String
    "cnf":{
        "jwk":{
            ... JSON Web Key ...
        }
    }
}
```

Additional custom claims may be added to the JWT and these values will added to the identity in the datastore. How these claims are added to the identity are specified by the `Claim to Attribute Mapping` in the node configuration.

## Example

The following example will attempt to authenticate the Thing with AM. If this fails because the Thing is unknown to AM, then the Thing will register itself with AM.

### Prerequisites

1. Install the following command-line tools:
    * curl
    * [jq](https://stedolan.github.io/jq/)
    * [go](https://golang.org/)
    * [git](https://git-scm.com/)
1. Build and install the jwt utilities in [iot-edge](https://github.com/ForgeRock/iot-edge):

    ```bash
    git clone https://github.com/ForgeRock/iot-edge.git
    cd iot-edge
    git checkout release/v7.1.0
    go install ./cmd/auth-jwt ./cmd/things-jwt
    ```

1. Install and configure AM as described in the [IoT evaluation guide](https://backstage.forgerock.com/docs/iot/7.1/evaluation-guide/before-you-start.html#install-am).
1. Set the following variables, changing the value of `amURL` to the base URL of your AM instance:
    
    ```bash
    amURL=http://am.localtest.me:8080/openam
    thingId=thingymabot
    tree=reg-tree
    keyfile=path/to/iot-edge/examples/resources/eckey1.key.pem
    certfile=path/to/iot-edge/examples/resources/thingmabot.cert.pem
    ```

### Initiate the Authentication
```bash
# Initiate the authentication request:
authCallback=$(curl \
    --silent \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0' \
    --header 'Content-Type: application/json' \
    --request POST \
    "$amURL/json/authenticate?authIndexType=service&authIndexValue=$tree")
```

### Responding to the Authenticate Thing Node

```bash
# Extract challenge:
challenge=$(echo "$authCallback" | \
    jq ".callbacks[0].output[0].value")

# Create the signed JWT for the Authenticate Thing Node:
signedJWT=$(auth-jwt -a "/" -s "$thingId" -c "$challenge" --key "$keyfile")

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
    "$amURL/json/authenticate?authIndexType=service&authIndexValue=$tree")

ssoToken=$(jq -r '.tokenId' <(echo $authResponse))
```

### Check the status of the Authentication Journey

```bash
if [ "$ssoToken" != "null" ]; then
    echo "Authentication complete $ssoToken"
else
    callbackId=$(echo "$authResponse" | \
    jq '[ .callbacks[0].output[] | select( .name | contains("id")) ]' | \
     jq  .[0].value)
    if [ "$callbackId" = '"jwt-pop-registration"' ]; then
        echo "Thing is unknown to AM, please continue to Registration"
    else
        echo "Something has gone wrong"
    fi
fi
```

### Responding to the Register Thing Node

```bash
# Extract challenge:
challenge=$(echo "$authResponse" | \
    jq ".callbacks[0].output[0].value")


# Create the signed registration JWT for the Register Thing Node:
signedJWT=$(auth-jwt -a "/" -s "$thingId" -c "$challenge" --key "$keyfile" --certificate $certfile)

# Modify callback:
regCallback=$(echo "$authResponse" | \
        jq ".callbacks[0].input[0].value = \"$signedJWT\"")

# Complete the registration request:
regResponse=$(curl \
    --silent \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0' \
    --header 'Content-Type: application/json' \
    --request POST \
    --data "$regCallback" \
    "$amURL/json/authenticate?authIndexType=service&authIndexValue=$tree")

ssoToken=$(jq -r '.tokenId' <(echo $regResponse))
echo "${ssoToken}"
```