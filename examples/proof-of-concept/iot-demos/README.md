# IoT Demos

## Prerequisites
Install:
 - Git
 - Docker
 
Clone the IoT repository and checkout the demo branch:  
```
git clone https://github.com/ForgeRock/iot-edge.git
cd iot-edge
git checkout iot-demos
cd examples/proof-of-concept/iot-demos
```

Get the Go docker image:
```
docker pull golang
```

Set the environment variable for the AM URL:
```
export AM_URL=https://example.forgeops.com/am
```

## Use case 1

Provisioning new smart devices manually and dynamically into the ForgeRock platform.

### Manual Registration

Configure the platform:
 - Create the IoT Service (Access Management Native Console)
 - Create a new Journey:
   - Name: `iot-journey`
   - Identity Object: `Things`
   - Nodes: `Authenticate Thing`
 - Create an identity for the smart device:
   - ID: `manual-smart-device`
   - Type: `device`
   - Keys: `{"keys":[{"use":"sig","kty":"EC","kid":"cbnztC8J_l2feNf0aTFBDDQJuvrd2JbLPoOAxHR2N8o=","crv":"P-256","alg":"ES256","x":"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4","y":"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw"}]}`

Start the Go docker image to simulate a smart device:
```
docker run -it -e AM_URL="$AM_URL" -v "$PWD"/things:/usr/src/things -w /usr/src/things golang
```

Run the `manual-registration` example to authenticate the device:
```
go run ./cmd/manual-registration -url "$AM_URL"
```

### Dynamic Registration

Configure the platform:
 - Modify `iot-journey` to include the `Register Thing` node
 - Select `Create Identity`
 - Add the following attributes:
   - `sub` : `uid`
   - `thingType` : `thingType`
   - `thingProperties` : `thingProperties`

Run the `dynamic-registration` example to dynamically register the device:
```
go run ./cmd/dynamic-registration -url "$AM_URL"
```

## Use case 2

Managing device identities in a central location along with user and service identities.

### Manage identities

Create user, device and service identities as required.

Identities can be modified and deleted through the Identities UI.

Relationships can be created between users and things. These relationships can then be queried and used, for example,
to manage access to user data or restrict user access to devices or services. Relationships can be created manually
through the UI or dynamically via custom endpoints.

## Use case 3

Manage user access to a particular device.

### Group based access

This use case will use a feature called [Dynamic OAuth 2.0 Authorization](https://backstage.forgerock.com/docs/am/7.1/authorization-guide/oauth2-authorization.html)
to assign OAuth 2.0 scopes to users based on what group they belong to. This allows devices to restrict access to users
if they are not in a particular group.

The device will obtain an access token for the user via the OAuth 2.0 Device Authorization Grant (Device Flow). This
means that the user does not have to share their credentials with the device and the device does not need an interactive
user interface.

Configure the platform:
- Modify the IoT Service to add OAuth 2.0 client
  - Add `view` and `maintain` scopes to the client
- Create groups for `Healthcare Professionals` and `Technicians`
- Add users to each group

Policies for making the decision about which scopes to add to the user's access token has already been added to the
configuration.

Run the `device-access` example to authenticate the user and gain access to the device:
```
go run ./cmd/device-access -url "$AM_URL"
```

Navigate to the URL provided and authenticate the user that requires access to the device.

The device will receive an access token for the user and inspect the scopes to decide what type of access the user is allowed.



## Deploy

Set environment variables:
```
export PLATFORM_PASSWORD=StrongPassword
export FQDN=example.forgeops.com
export NAMESPACE=iot-demo
export CLUSTER=forgerock
export ZONE=us-east1
export PROJECT=fr-iot-demos
```

Deploy the ForgeOps IoT platform:
```
./deploy.sh
```

Use the `(uid=admin user)` password provided at the end of the deployment script and populate the demo identities,
for example:
```
./add-identities.sh zIg1LChqItAh7imtQSopLxn5uGlnMycc
```
