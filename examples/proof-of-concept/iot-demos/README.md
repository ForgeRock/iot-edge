# IoT Demos

## Prepare Demo Environment

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

Start the Go docker image to simulate a smart device:
```
docker run -it -e AM_URL="$AM_URL" -v "$PWD"/things:/usr/src/things -w /usr/src/things golang
```

## Use Case: Devices Provisioning

Provisioning new smart devices manually and dynamically into the ForgeRock platform.

### Manual Registration

Configure the platform:
 - Create a new Journey:
   - Name: `iot-journey`
   - Identity Object: `Things`
   - Nodes: `Authenticate Thing`
 - Create an identity for the smart device:
   - ID: `manual-smart-device`
   - Type: `device`
   - Keys: `{"keys":[{"use":"sig","kty":"EC","kid":"cbnztC8J_l2feNf0aTFBDDQJuvrd2JbLPoOAxHR2N8o=","crv":"P-256","alg":"ES256","x":"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4","y":"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw"}]}`

Run the `device-authenticate` example to authenticate the device:
```
go run ./cmd/device-authenticate -url "$AM_URL"
```
The device should authenticate successfully and receive an SSO token.

### Dynamic Registration

Configure the platform:
 - Modify `iot-journey` to include the `Register Thing` node
 - Select `Create Identity`
 - Add the following attributes:
   - `sub` : `uid`
   - `thingType` : `thingType`

Run the `device-register` example to dynamically register the device:
```
go run ./cmd/device-register -url "$AM_URL"
```
The device should register successfully and receive an SSO token.

## Use Case: Device Identity Management

Managing device identities in a central location along with user identities.

### Manage Device Status

Change the `Status` of the `dynamic-smart-device` to `inactive` and run:
```
go run ./cmd/device-authenticate -url "$AM_URL" -name dynamic-smart-device
```
The device should fail to authenticate, receiving a `401 Unauthorized` response.

Change the `Status` of the `dynamic-smart-device` to `active` and run:
```
go run ./cmd/device-authenticate -url "$AM_URL" -name dynamic-smart-device
```
The device should receive an SSO token.

### Manage Device and User Relationships

Relationships can be created between users and things. These relationships can then be queried and used, for example,
to manage access to user data or restrict user access to devices or services. Relationships can be created manually
through the UI or dynamically via custom endpoints.

Create a relationship between a user and a device:
- In the Platform Console, create a new user to associate with a device
- From Identities -> Manage -> Things select the `dynamic-smart-device`
- In the Users tab, add the new user you created

Query the device and user relationship:
- In Identity Management Native Console, go to Dashboards -> Relationships
- On the left, search for the user to view all their associated devices
- On the right, search for the device to view all its associated users

## Use Case: Device Access Control

Manage user access to a particular device.

### Group based access

This use case will use a feature called [Dynamic OAuth 2.0 Authorization](https://backstage.forgerock.com/docs/am/7.1/authorization-guide/oauth2-authorization.html)
to assign OAuth 2.0 scopes to users based on what group they belong to. This allows devices to restrict access to users
if they are not in a particular group.

The device will obtain an access token for the user via the OAuth 2.0 Device Authorization Grant (Device Flow). This
means that the user does not have to share their credentials with the device and the device does not need an interactive
user interface.

Configure the platform:
- Create another user so that you have two users
- In the Access Management Native Console
  - Create the IoT Service
    - Select `Create OAuth 2.0 Client` and `Create OAuth 2.0 JWT Issuer` and save
  - Modify the `forgerock-iot-oauth2-client` OAuth 2.0 client
    - Add `view` and `maintain` scopes
  - Create groups for `Viewers` and `Maintainers`
  - Add one user to each group

Policies for making the decision about which scopes to add to the user's access token has already been added to the
configuration.

Run the `device-access` example to authenticate the user and gain access to the device:
```
go run ./cmd/device-access -url "$AM_URL"
```

Navigate to the URL provided and authenticate the user that requires access to the device.

The device will receive an access token for the user and inspect the scopes to decide what type of access the user is allowed.

## Use Case: Integration with Google Cloud IoT Core

Integrate with Google Cloud Platform IoT Core and manage devices in either ForgeRock or GCP.

### Configuration

Configure GCP for IoT:
- [Create a project and enable IoT Core](https://cloud.google.com/iot/docs/how-tos/getting-started) 
- [Create a device registry](https://cloud.google.com/iot/docs/how-tos/devices#iot-core-create-registry)
- [Create a service account](https://cloud.google.com/docs/authentication/production#create_service_account)
  - Give the service account the `Cloud IoT Provisioner` role.
  - Create a key for the service account and download the credentials in JSON format.

Configure ForgeRock GCP IoT Core Connector:
- Create a new `Google Cloud Platform IoT Core Connector` in Identity Management Native Console
  - Connector Name: `GCPIoTCore`
- Supply the following GCP details:
  - Project ID
  - Registry ID
  - Region
  - Service account credentials in JSON format

### Synchronise device from ForgeRock to GCP

Devices can be dynamically registered in the ForgeRock Platform and synchronised to the GCP Registry.

Configure the platform:
- Enable Reconciliation from FR to GCP

#### Register new devices and publish device telemetry

[comment]: <> (![Publish]&#40;docs/device-publish.png&#41;)

Run the `gcp-iot` example to register a device and publish device status to GCP
(replace `projectID`, `registryID` and `region` with your GCP details):
```
go run cmd/gcp-iot/main.go --url "$AM_URL" --projectID iot-project --registryID iot-registry --region europe-west1
```

The device will be dynamically registered with FR and synchronized to GCP. A new device called `dynamic-gcp-device`
should be visible in the GCP Device Registry. The state provided should be visible under the `Configuration & State` tab.

[comment]: <> (### Synchronise device from GCP to ForgeRock)

[comment]: <> (Configure the platform:)

[comment]: <> (- Disable Reconciliation from FR to GCP)

[comment]: <> (- Enable Reconciliation from GCP to FR)

[comment]: <> (Create a new device in CGP IoT Core. )

[comment]: <> (View the newly synchronised devices in the ForgeRock Platform.)

[comment]: <> (#### Authenticate and authorize existing device)

[comment]: <> (The device's public key is synchronised to the ForgeRock Platform, which means that the device can now authenticate)

[comment]: <> (with ForgeRock to access additional features.)

[comment]: <> (The device can now request an OAuth 2.0 access token, which can be used to access 3rd party services.)

[comment]: <> (![Authorize]&#40;docs/device-authorize.png&#41;)

[comment]: <> (Run the `device-authorize` example to authenticate the device and to request an access token:)

[comment]: <> (```)

[comment]: <> (go run ./cmd/device-authorize -url "$AM_URL" -name 2698309725841565 -keyid 2698309725841565-0)

[comment]: <> (```)

[comment]: <> (Access tokens can be issued as JWTs to allow services to do their own verification and access additional claims.)

## Deploy ForgeOps IoT

This will deploy Version 7.1.0 of the ForgeOps CDK, configured for IoT, to Google Kubernetes Engine.

Follow the ForgeOps documentation to install the
[third party software](https://backstage.forgerock.com/docs/forgeops/7.1/cdk/cloud/setup/gke/sw.html) and
[obtain the GKE cluster details](https://backstage.forgerock.com/docs/forgeops/7.1/cdk/cloud/setup/gke/clusterinfo.html).

Set the following environment variables:
```
PROJECT     - The name of the Google Cloud project that contains the cluster
CLUSTER     - The cluster name
ZONE        - The Google Cloud zone in which the cluster resides
NAMESPACE   - The namespace to use in your cluster
FQDN        - The fully qualified domain name of your deployment
```

for example:
```
export PROJECT=fr-iot-demos
export CLUSTER=forgerock
export ZONE=us-east1
export NAMESPACE=iot-demo
export FQDN=example.forgeops.com
```

After installing the Google Cloud SDK, authenticate and configure the SDK:
```
gcloud auth login
gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT
```

Deploy the ForgeOps IoT platform:
```
./deploy.sh
```

The deployment script will perform the following tasks:
- Checkout the ForgeOps and ForgeRock IoT Git repositories
- Apply the IoT LDAP schema for Things to DS
- Configure AM:
   - with IoT identity repository objects and attributes
   - as an OAuth 2.0 Authorization Server
   - with the secrets required for IoT dynamic registration and OAuth 2.0 features
- Configure IDM:
   - with the Thing managed object schema
   - for User and Thing relationships
- Create the Kubernetes namespace and deploy the platform with Scaffold

When the script is complete it will print out the connection details for the platform.

[comment]: <> (### Create Demo Identities)

[comment]: <> (Use the `&#40;uid=admin user&#41;` password provided at the end of the deployment script and populate the demo identities,)

[comment]: <> (for example:)

[comment]: <> (```)

[comment]: <> (./add-identities.sh zIg1LChqItAh7imtQSopLxn5uGlnMycc)

[comment]: <> (```)

[comment]: <> (Once the identities are added you have to reset their passwords in order for them to be able to authenticate.)
