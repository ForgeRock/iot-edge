# ForgeOps for IoT

This directory contains resources for deploying Things with the ForgeRock Identity Platform to Kubernetes using ForgeOps.

### Get Started

Install the third party software by following the instructions in the
[ForgeOps docs](https://backstage.forgerock.com/docs/forgeops/7.1/cdk/minikube/setup/sw.html).
Additionally, install [mkcert](https://github.com/FiloSottile/mkcert) for making locally-trusted development certificates.

Clone this repo:
```
git clone https://github.com/ForgeRock/iot-edge.git
cd iot-edge
git checkout release/v7.1.0
cd deployments/forgeops
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

### Using the Platform for Things
Once the platform is running we can register and authenticate a thing via the `authenticate` endpoint and perform actions like authorization and retrieving attributes via the `things` endpoint. This can either be done with the IoT SDK or by using the endpoints directly. The `things` endpoint in AM provides IoT-specific functionality. For example, a thing can request an OAuth 2.0 access token without having to know the credentials of the OAuth 2.0 client acting on its behalf.

Before a thing can use the `things` endpoint, it must be registered with the platform and have a valid session token. A thing identity can be registered via the platform UI:

1. Open the [Thing List](https://iot.iam.example.com/platform/?realm=root#/managed-identities/managed/thing).
1. Click the `New Thing` button.
1. Enter the following values in the pop up window:
    * ID: `thingymabot`
    * Type: `device`
1. Click `Save` to create the thing identity.
1. An entry for `thingymabot` will appear in the `Thing List`, click on the entry.
1. Click the `Reset Password` button.
1. Enter the password `5tr0ngG3n3r@ted` in the pop up window and click the `Reset Password` button.

Now that `thingymabot` exists in the platform, it can authenticate using its own credentials:
```
curl --request POST 'https://iot.iam.example.com/am/json/realms/root/authenticate?realm=/' \
    --header 'Content-Type: application/json' \
    --header 'X-OpenAM-Username: thingymabot' \
    --header 'X-OpenAM-Password: 5tr0ngG3n3r@ted' \
    --header 'Accept-API-Version: resource=2.0, protocol=1.0'
```

Save the `tokenId` received from this request to a variable:
```
export thingTokenId=FJo9Rl....AAIwMQ..*
```

With this session token, `thingymabot` can request an OAuth 2.0 access token from the `things` endpoint:
```
curl --request POST 'https://iot.iam.example.com/am/json/things/*?_action=get_access_token' \
    --header 'Accept-API-Version: protocol=2.0,resource=1.0' \
    --header 'Content-Type: application/json' \
    --header "Cookie: iPlanetDirectoryPro=${thingTokenId}" \
    --data-raw '{
        "scope":["publish"]
    }'
```

If the request is valid and authorised, then the platform will respond with the standard OAuth 2.0 Access Token Response. For example:
```
{
    "access_token":"1b7JX5BYt7OkBIxEBy0gavzX7aA",
    "refresh_token":"5rI_8TxznBppLWBkCOsboUNBW08",
    "scope":"publish",
    "token_type":"Bearer",
    "expires_in":3599
}
```

### Run Functional Tests

The functional test framework, Anvil, can be run against the ForgeOps IoT Platform to verify that all the IoT SDK and
IoT Gateway features work correctly.

Start the platform before running the tests:
```
./run.sh $(PWD)/../../tests/iotsdk/testdata/forgeops 6KZjOxJU1xHGWHI0hrQT24Fn
```

Run the functional tests:
```
cd ../../
./run.sh anvil -deployment=platform -url=https://iot.iam.example.com/am -password=6KZjOxJU1xHGWHI0hrQT24Fn
```
