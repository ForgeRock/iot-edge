# IoT Authentication Nodes

## Overview

Out of the box, AM provides the following nodes for IoT Things:

* [Authenticate Thing Node](#authenticate-thing-node)
* [Register Thing Node](#register-thing-node)

This document will describe how to respond to callbacks requested by the nodes when not using the IoT SDK. The JWTs
supplied in response to the callbacks may contain additional custom claims. All claims will be added to the transient
state of the Authentication Tree, keyed under `org.forgerock.am.iot.jwt.pop.verified_claims`.

Consult the [product documentation](https://backstage.forgerock.com/docs/am/7.1/authentication-guide/auth-node-configuration-hints.html#thing-auth-nodes)
for instruction on how to configure the nodes.

## Authenticate Thing Node

This node supports two JWT authentication methods:
* [Proof of Possession](#pop-auth)
* [Client Assertion](#ca-auth)

To use this node, a Thing must:
* Be registered with AM.
* Have an asymmetric key pair with the public part known to AM.

### Proof Of Possession <a name="pop-auth"></a>

This method authenticates a Thing using [JWT Proof of Possession](https://datatracker.ietf.org/doc/html/rfc7800).

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array
containing:
* An `id` object with the value `jwt-pop-authentication`.
* A `value` object with a challenge from AM.

The Thing must create a signed JWT and return it as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
    "authId": "eyJ0eXA...",
    "callbacks": [
        {
            "type": "HiddenValueCallback",
            "output": [
                {
                    "name": "value",
                    "value": "kwXyn2xSQjtg_AExMAFM1g"
                },
                {
                    "name": "id",
                    "value": "jwt-pop-authentication"
                }
            ],
            "input": [
                {
                    "name": "IDToken1",
                    "value": "jwt-pop-authentication"
                }
            ]
        }
    ]
}
```
</td><td>

```json
{
    "authId": "eyJ0eXA...",
    "callbacks": [
        {
            "type": "HiddenValueCallback",
            "output": [
                {
                    "name": "value",
                    "value": "kwXyn2xSQjtg_AExMAFM1g"
                },
                {
                    "name": "id",
                    "value": "jwt-pop-authentication"
                }
            ],
            "input": [
                {
                    "name": "IDToken1",
                    "value": "<Signed Proof of Possession JWT>"
                }
            ]
        }
    ]
}
```
</td></tr></table>

Signed Proof of Possession JWT example:

Header
```json
{
  "alg" : "ES256"
}
```
Payload
```json
{
  "sub" : "manual-pop-thing",
  "aud" : "/", 
  "iat" : 1650376224,
  "exp" : 1650376524,
  "nonce" : "kwXyn2xSQjtg_AExMAFM1g",
  "cnf" : {
    "kid" : "U_KPW5951sqqiTy1GvBMIqzKe2DM13PU0y8lplpYigg="
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, a unique identifier for the Thing |
| `aud` | Audience, the AM realm path or one of the additional audience values configure in the _Authenticate Thing_ node |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |
| `nonce` | The challenge from AM |
| `cnf.kid` | Key ID of the Thing's public key known to AM |

### Client Assertion <a name="ca-auth"></a>

This method authenticates a Thing using a [JWT Bearer token](https://datatracker.ietf.org/doc/html/rfc7523#section-3).

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array
containing:
* An `id` object with the value `client_assertion`.
* An empty `value` object.

The Thing must create a signed JWT and return it as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
    "authId": "eyJ0eXA...",
    "callbacks": [
        {
            "type": "HiddenValueCallback",
            "output": [
                {
                    "name": "value",
                    "value": ""
                },
                {
                    "name": "id",
                    "value": "client_assertion"
                }
            ],
            "input": [
                {
                    "name": "IDToken1",
                    "value": "client_assertion"
                }
            ]
        }
    ]
}
```
</td><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": ""
        },
        {
          "name": "id",
          "value": "client_assertion"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "<Signed Assertion JWT>"
        }
      ]
    }
  ]
}
```
</td></tr></table>

Signed Assertion JWT example:

Header
```json
{
  "alg" : "ES256",
  "kid" : "U_KPW5951sqqiTy1GvBMIqzKe2DM13PU0y8lplpYigg="
}
```
Payload
```json
{
   "sub" : "manual-oauth-thing",
   "iss" : "manual-oauth-thing",
   "aud" : "http://am.localtest.me:8080/am/oauth2/access_token",
   "iat" : 1650376224,
   "exp" : 1650376524
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |
| `kid` | Key ID of the Thing's public key known to AM |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, a unique identifier for the Thing |
| `iss` | Issuer of the JWT, must be the Thing ID |
| `aud` | Audience, one of the OAuth token endpoints or additional audience values configure in the node |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |

## Register Thing Node

This node supports four JWT registration methods:
* [Proof of Possession & Certificate](#pop-cert-reg)
* [Proof of Possession & Software Statement](#pop-sw-stmt-reg)
* [Proof of Possession](#pop-reg)
* [Software Statement](#sw-stmt-reg)

### Proof of Possession & Certificate <a name="pop-cert-reg"></a>

This method registers a Thing using [JWT Proof of Possession](https://datatracker.ietf.org/doc/html/rfc7800) and a
certificate, with a Certificate Authority as a trusted third party.

To use it, a Thing must have:
* an asymmetric key pair
* an X.509 certificate that has been signed by a Certificate Authority known to AM

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array
containing two objects:
* An `id` object with the value `jwt-pop-registration`.
* A `value` object with a challenge from AM.

The Thing must create a signed JWT containing the certificate and return it as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "Vg7McIhuLQ-qwmrMhJHkOw"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "jwt-pop-registration"
        }
      ]
    }
  ]
}
```
</td><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "Vg7McIhuLQ-qwmrMhJHkOw"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "<Signed Proof of Possession JWT>"
        }
      ]
    }
  ]
}
```
</td></tr></table>

Signed Proof of Possession JWT example:

Header
```json
{
  "alg" : "ES256"
}
```
Payload
```json
{
  "sub" : "dynamic-thing",
  "aud" : "/", 
  "iat" : 1650378867,
  "exp" : 1650379167,
  "nonce" : "Vg7McIhuLQ-qwmrMhJHkOw",
  "thingType" : "device",
  "cnf" : {
    "jwk" : {
      "crv" : "P-256",
      "kid" : "U_KPW5951sqqiTy1GvBMIqzKe2DM13PU0y8lplpYigg=",
      "kty" : "EC",
      "use" : "sig",
      "x5c" : [ "MIIBhj..." ],
      "x" : "HBdBSlCTLpIlYedOTPP3eQV5jxZx5OE_32zFwBEMZ1Q",
      "y" : "bxK8GunOG4QBNw0GCdp5i8AocsCwTlQaSpfq0y8D0a4"
    }
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, a unique identifier for the Thing |
| `aud` | Audience, the AM realm path or one of the additional audience values configure in the _Authenticate Thing_ node |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |
| `nonce` | The challenge from AM |
| `thingType` | Thing Type, either `device`, `service` or `gateway` |
| `cnf.jwk` | Public key and certificate of the Thing in JSON Web Key form, see [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517)|

### Proof of Possession & Software Statement <a name="pop-sw-stmt-reg"></a>

This method registers a Thing using [JWT Proof of Possession](https://datatracker.ietf.org/doc/html/rfc7800) and
a [software statement](https://datatracker.ietf.org/doc/html/rfc7591#section-2.3), with a Software Publisher as a
trusted third party.

To use it, a Thing must have:
* an asymmetric key pair
* a software statement that has been signed by a Software Publisher known to AM

The node will send two callbacks to the Thing of type `HiddenValueCallback`:
* One callback will have an `output` array containing:
  * An `id` object with the value `jwt-pop-registration`.
  * A `value` object with a challenge from AM.
* The other callback will have an `output` array containing:
   * An `id` object with the value `software_statement`.
   * An empty `value` object.

The Thing must create a signed JWT and return it along with the software statement as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "MP7Uu8u6V66vuqD4nnMFEQ"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "jwt-pop-registration"
        }
      ]
    },
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": ""
        },
        {
          "name": "id",
          "value": "software_statement"
        }
      ],
      "input": [
        {
          "name": "IDToken2",
          "value": "software_statement"
        }
      ]
    }
  ]
}
```
</td><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "MP7Uu8u6V66vuqD4nnMFEQ"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "<Signed Proof of Possession JWT>"
        }
      ]
    },
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": ""
        },
        {
          "name": "id",
          "value": "software_statement"
        }
      ],
      "input": [
        {
          "name": "IDToken2",
          "value": "<Signed Software Statement JWT>"
        }
      ]
    }
  ]
}
```
</td></tr></table>

Signed Proof of Possession JWT example:

Header
```json
{
  "alg" : "ES256",
  "typ" : "JWT"
}
```
Payload
```json
{
  "sub" : "8a3ee2d7-75d5-434d-b24b-b9bad2a69660",
  "aud" : "/",
  "exp" : 1650380168,
  "iat" : 1650379868,
  "nonce" : "MP7Uu8u6V66vuqD4nnMFEQ",
  "thingType" : "device",
  "cnf" : {
    "kid" : "mVQ7pJhc-jyHKX4UJtpreJQZTrOZr7ozmJ2xtkezDIY="
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, a unique identifier for the Thing |
| `aud` | Audience, the AM realm path or one of the additional audience values configure in the _Authenticate Thing_ node |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |
| `nonce` | The challenge from AM |
| `thingType` | Thing Type, either `device`, `service` or `gateway` |
| `cnf.kid` | Key ID of the Thing's public key known to AM |

Signed Software Statement JWT example:

Header
```json
{
  "alg" : "ES256",
  "kid" : "gLcQhotEZygUuVUrt3Z6azql3dVfqQS7lo3vereyU7Y="
}
```
Payload
```json
{
  "iss" : "https://soft-pub.example.com",
  "jwks" : {
    "keys" : [ {
      "alg" : "ES256",
      "crv" : "P-256",
      "kid" : "wL1NZEf3kID9zz-MjJDw5KX2JZW8QD2JXCeOLTm1cKI=",
      "kty" : "EC",
      "use" : "sig",
      "x" : "r2K-82fbzf4VRjelX8lJCwzGz4j83WhDnhFMFZ6NHmQ",
      "y" : "TNGUstw6SD0lAesOSpQ44UrMzP9ypEJiW8_8-1JsoNw"
    } ]
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |
| `kid` | Key ID of the Software Publisher's public key |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `iss` | The Software Publisher's unique identifier |
| `jwks` | A JWK set containing the Thing's public key(s) |

### Proof of Possession <a name="pop-reg"></a>

This method registers a Thing using [JWT Proof of Possession](https://datatracker.ietf.org/doc/html/rfc7800),
without a trusted third party.

To use it, a Thing must have:
* an asymmetric key pair

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array
containing:
* An `id` object with the value `jwt-pop-registration`.
* A `value` object with a challenge from AM.

The Thing must create a signed JWT and return it as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "Vg7McIhuLQ-qwmrMhJHkOw"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "jwt-pop-registration"
        }
      ]
    }
  ]
}
```
</td><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": "Vg7McIhuLQ-qwmrMhJHkOw"
        },
        {
          "name": "id",
          "value": "jwt-pop-registration"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "<Signed Proof of Possession JWT>"
        }
      ]
    }
  ]
}
```
</td></tr></table>

Signed Proof of Possession JWT example:

Header
```json
{
  "alg" : "ES256"
}
```
Payload
```json
{
  "sub" : "009af66f-7a9a-4eca-a3a1-04bdf5be0056",
  "aud" : "/",
  "iat" : 1650380842,
  "exp" : 1650381142,
  "nonce" : "1JDKOYQ2A2reNR_Zqnnmeg",
  "thingType" : "device",
  "cnf" : {
    "jwk" : {
      "crv" : "P-256",
      "kid" : "VC_sNEp6viFCWW3fX2KqyC6XOPMGhjF5J_O74m-TTas=",
      "kty" : "EC",
      "use" : "sig",
      "x" : "7cHWJnKzIS4uYkrqgDLLeqZ93fuj-7VvqEZPFvPu8gU",
      "y" : "6lB5RpmjMYbNTzYX3ewNzX1n3SwNC-3XHO4Y3YtVIq8"
    }
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `sub` | Subject, a unique identifier for the Thing |
| `aud` | Audience, the AM realm path or one of the additional audience values configure in the _Authenticate Thing_ node |
| `iat` | Time at which the JWT was issued |
| `exp` | Expiration time of the JWT |
| `nonce` | The challenge from AM |
| `thingType` | Thing Type, either `device`, `service` or `gateway` |
| `cnf.jwk` | Public key of the Thing in JSON Web Key form, see [RFC7517](https://datatracker.ietf.org/doc/html/rfc7517) |

### Software Statement <a name="sw-stmt-reg"></a>

This method registers a Thing using a [software statement](https://datatracker.ietf.org/doc/html/rfc7591#section-2.3)
and a Software Publisher as a trusted third party, without proof of possession.

To use it, a Thing must have:
* a software statement that has been signed by a Software Publisher known to AM

The node will send a callback to the Thing of type `HiddenValueCallback`. The callback will have an `output` array
containing:
* An `id` object with the value `software_statement`.
* An empty `value` object.

The Thing must return the software statement as in the following example:

<table><tr><td> Callback </td> <td> Response </td></tr>
<tr><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": ""
        },
        {
          "name": "id",
          "value": "software_statement"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "software_statement"
        }
      ]
    }
  ]
}
```
</td><td>

```json
{
  "authId": "eyJ0eXA...",
  "callbacks": [
    {
      "type": "HiddenValueCallback",
      "output": [
        {
          "name": "value",
          "value": ""
        },
        {
          "name": "id",
          "value": "software_statement"
        }
      ],
      "input": [
        {
          "name": "IDToken1",
          "value": "<Signed Software Statement JWT>"
        }
      ]
    }
  ]
}
```
</td></tr></table>

Signed Software Statement JWT example:

Header
```json
{
  "alg" : "ES256",
  "kid" : "gLcQhotEZygUuVUrt3Z6azql3dVfqQS7lo3vereyU7Y="
}
```
Payload
```json
{
  "iss" : "https://soft-pub.example.com",
  "jwks" : {
    "keys" : [ {
      "alg" : "ES256",
      "crv" : "P-256",
      "kid" : "wL1NZEf3kID9zz-MjJDw5KX2JZW8QD2JXCeOLTm1cKI=",
      "kty" : "EC",
      "use" : "sig",
      "x" : "r2K-82fbzf4VRjelX8lJCwzGz4j83WhDnhFMFZ6NHmQ",
      "y" : "TNGUstw6SD0lAesOSpQ44UrMzP9ypEJiW8_8-1JsoNw"
    } ]
  }
}
```

Required Headers:

| Claim | Value |
| --- | ----------- |
| `alg` | Algorithm used to sign the JWT |
| `kid` | Key ID of the Software Publisher's public key |

Required Claims:

| Claim | Value |
| --- | ----------- |
| `iss` | The Software Publisher's unique identifier |
| `jwks` | A JWK set containing the Thing's public key(s) |

## Example

The following example will attempt to authenticate the Thing with AM. If this fails, because the Thing is unknown to AM,
the Thing will register itself with AM.

### Prerequisites

1. Install the following command-line tools:
    * curl
    * [jq](https://stedolan.github.io/jq/)
    * [go](https://golang.org/)
    * [git](https://git-scm.com/)
1. Clone the [iot-edge](https://github.com/ForgeRock/iot-edge) repo:

    ```bash
    git clone https://github.com/ForgeRock/iot-edge.git
    cd iot-edge
    ```

1. Install and configure AM as described in the [IoT evaluation guide](https://backstage.forgerock.com/docs/iot/7.1/evaluation-guide/before-you-start.html#install-am).
1. Set the following variables, changing the value of `amURL` to the base URL of your AM instance:
    
    ```bash
    amURL=http://am.localtest.me:8080/openam
    thingId=thingymabot
    tree=reg-tree
    keyfile=$(pwd)/examples/resources/eckey1.key.pem
    certfile=$(pwd)/examples/resources/thingymabot.cert.pem
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
signedJWT=$(go run ./cmd/auth-jwt -a "/" -s "$thingId" -c "$challenge" --key "$keyfile")

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
signedJWT=$(go run ./cmd/auth-jwt -a "/" -s "$thingId" -c "$challenge" --key "$keyfile" --certificate $certfile)

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