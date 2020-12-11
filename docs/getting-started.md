# Getting Started

## Introduction

<img src="iot-edge-components.svg" width="400"/>

### IoT SDK

The _IoT SDK_ enables a _thing_, which can be either a physical _device_ or a software _service_, to register and
authenticate without human interaction. Once registered, the _thing_ will be represented by a digital identity in the
ForgeRock Identity Platform and can authenticate itself in order to interact with the platform tier. The IoT SDK
can communicate directly with the platform using HTTP(S) or via the IoT Gateway using CoAP(S).

### IoT Gateway
The _IoT Gateway_ is an application that enables more constrained devices to interact with the ForgeRock Identity
Platform by acting as a proxy between a _thing_ and the Platform.

## Evaluate ForgeRock IoT

This section covers the tasks you need to quickly get a test or demo environment running. It will guide you through
configuring ForgeRock Access Management (AM) and running the IoT SDK and Gateway examples.

### Install prerequisite software

The IoT SDK and Gateway has been developed in the Go programming language and to run the examples you require
[Go 1.15 or later](https://golang.org/doc/install).

You also require [Git](https://git-scm.com/) for downloading the source code and running the examples.  

### Get the example code

Clone this repository:
```bash
git clone git@github.com:ForgeRock/iot-edge.git
```

This will create a directory named `iot-edge`. The instructions for running the examples will assume this as your
current directory:

```bash
cd iot-edge
```

### Install and configure AM

The examples require AM to be installed with a fully qualified domain name of `am.localtest.me`, using port `8080`.
Follow the [AM Evaluation Guide](https://backstage.forgerock.com/docs/am/7/eval-guide/) to quickly set up an instance.

Log in to AM and go to [Services](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/services):

- Add the _IoT Service_
- Select _Create OAuth 2.0 Client_ and _Create OAuth 2.0 JWT Issuer_
- Save Changes
- Add the _OAuth2 Provider_ service

Go to the [IoT OAuth 2.0 Client](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/applications-oauth2-clients/clients/edit/forgerock-iot-oauth2-client):

- Add `publish` to _Scope(s)_
- Save Changes

Create an [authentication tree](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/authentication-trees) called `auth-tree`:

<img src="auth-tree.png" width="400"/></br>

Create a second authentication tree called `reg-tree` and enable _Create Identity_ for the _Register Thing_ node:

<img src="reg-tree.png" width="600"/></br>

Go to the [default keystore mappings](http://am.localtest.me:8080/am/ui-admin/#configure/secretStores/KeyStoreSecretStore/edit/default-keystore)
and add the mapping: _Secret ID_: `am.services.iot.cert.verification`, _Alias_: `es256test`. The CA certificate used in
this example is one of the test certificates (es256test) that AM includes by default. This mapping tells the
_Register Thing_ node what key to use when verifying the registration certificate.

### Run the IoT SDK examples

#### Manual Registration

<img src="manual-registration.png" width="520"/></br>

This example will authenticate and request an access token for the thing. It requires the thing to be in possession
of an asymmetric key pair for signing.

Before running the example, [register the thing manually](getting-started.md#register-identity) using `manual-thing` as
the thing's ID.

Run the [example](https://github.com/ForgeRock/iot-edge/blob/master/examples/thing/simple/main.go):
```bash
./run.sh example "thing/simple" \
    -name "manual-thing" \
    -url "http://am.localtest.me:8080/am" \
    -audience "/" \
    -realm "/" \
    -tree "auth-tree" \
    -secrets "./examples/resources/example.secrets"
```

#### Dynamic Registration
    
<img src="dynamic-registration.png" width="650"/></br>

This example will create a new identity, authenticate and request an access token for the thing. It requires the thing
to be in possession of an asymmetric key pair for signing, and a CA signed X.509 certificate containing the key pair's
public key.

Run the [example](https://github.com/ForgeRock/iot-edge/blob/master/examples/thing/cert-registration/main.go):
```bash
./run.sh example "thing/cert-registration" \
    -name "dynamic-thing" \
    -url "http://am.localtest.me:8080/am" \
    -audience "/" \
    -realm "/" \
    -tree "reg-tree"
```

### Run the IoT Gateway examples

The [IoT Gateway](https://github.com/ForgeRock/iot-edge/blob/master/cmd/gateway/main.go) has its own identity in AM,
which similar to a Thing, can be manually or dynamically registered. When manually registered, the gateway requires an
asymmetric key pair for signing. When dynamically registered, the gateway requires an asymmetric key pair for signing,
and a CA signed X.509 certificate containing the key pair's public key. 

#### Manual Registration

This example will start the gateway and authenticate it.

Before running the example, [register the gateway manually](getting-started.md#register-identity) using `manual-gateway`
as the gateway's ID.

Run the gateway:

```bash
./run.sh gateway \
    --name "manual-gateway" \
    --url "http://am.localtest.me:8080/am" \
    --audience "/" \
    --realm "/" \
    --tree "auth-tree" \
    --kid "pop.cnf" \
    --key "./examples/resources/eckey1.key.pem" \
    --address ":5683" \
    -d
```

The message `IoT Gateway server started` will appear if the `manual-gateway` has started up and authenticated itself
successfully.

In a different terminal window, [connect a thing to the gateway](getting-started.md#connect-to-the-thing-gateway).

To stop the gateway process, press `Ctrl+C` in the window where the process is running.

#### Dynamic Registration

This example will start the gateway, register and authenticate it.

Run the gateway:

```bash
./run.sh gateway \
    --name "dynamic-gateway" \
    --url "http://am.localtest.me:8080/am" \
    --audience "/" \
    --realm "/" \
    --tree "reg-tree" \
    --key "./examples/resources/eckey1.key.pem" \
    --cert "./examples/resources/dynamic-gateway.cert.pem" \
    --address ":5683" \
    -d
```

The message `IoT Gateway server started` will appear if the gateway has started up, registered and authenticated
itself successfully.

In a different terminal window, [connect a thing to the gateway](getting-started.md#connect-to-the-thing-gateway).

To stop the gateway process, press `Ctrl+C` in the window where the process is running.

#### Connect to the IoT Gateway

This example will connect a thing to the IoT Gateway. Once the thing has connected it will authenticate and request
an access token.

Before running the example, [register the thing manually](getting-started.md#register-identity) using `gateway-thing`
as the thing's ID.

Run the SDK [example](https://github.com/ForgeRock/iot-edge/blob/master/examples/thing/simple/main.go)
to connect the thing to the gateway:

```bash
./run.sh example "thing/simple" \
    -name "gateway-thing" \
    -url "coap://:5683" \
    -keyfile "./examples/resources/eckey1.key.pem"
```

### Register Identity

Use curl and AM's REST endpoints to manually register an identity for a thing or the gateway.

Get an admin SSO token:

```bash
curl --request POST 'http://am.localtest.me:8080/am/json/authenticate' \
--header 'Content-Type: application/json' \
--header 'X-OpenAM-Username: amAdmin' \
--header 'X-OpenAM-Password: changeit' \
--header 'Accept-API-Version: resource=2.0, protocol=1.0'
```

Save the `tokenId` received from this request to a variable:

```bash
tokenId="5oXAB6....lMxAAA.*"
```

Set the ID of the identity to register. Change the value as specified in the example's instructions:

```bash
ID=thing-or-gateway
```

Register an identity for a thing:

```bash
curl -v --request PUT "http://am.localtest.me:8080/am/json/realms/root/users/${ID}" \
--header 'Content-Type: application/json' \
--header 'Accept-Api-Version: resource=4.0, protocol=2.1' \
--cookie "iPlanetDirectoryPro=${tokenId}" \
--data '{
    "userPassword": "5tr0ngG3n3r@ted",
    "thingType": "device",
    "thingKeys": "{\"keys\":[{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\"}]}"
}'
```

Register an identity for the gateway:

```bash
curl -v --request PUT "http://am.localtest.me:8080/am/json/realms/root/users/${ID}" \
--header 'Content-Type: application/json' \
--header 'Accept-Api-Version: resource=4.0, protocol=2.1' \
--cookie "iPlanetDirectoryPro=${tokenId}" \
--data '{
    "userPassword": "5tr0ngG3n3r@ted",
    "thingType": "gateway",
    "thingKeys": "{\"keys\":[{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\"}]}"
}'
```

## Next Steps

#### [Develop a client application with the IoT SDK](develop-a-client-application.md)

#### [Build the IoT Gateway for your target system](building-the-gateway.md)
