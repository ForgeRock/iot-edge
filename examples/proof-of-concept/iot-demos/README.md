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
go run ./cmd/manual-registration -url $AM_URL
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
go run ./cmd/dynamic-registration -url $AM_URL
```

## Use case 2

Managing device identities in a central location along with user and service identities.

### Manage identities

Create user, device and service identities as required.

Identities can be modified and deleted through the Identities UI.

Relationships can be created between users and things. These relationships can then be queried and used, for example,
to manage access to user data or restrict user access to devices or services. Relationships can be created manually
through the UI or dynamically via custom endpoints.

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
