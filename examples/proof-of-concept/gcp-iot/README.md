## Google Cloud Platform IoT Core Integration

The ForgeRock Identity Platform allows you to manage user and thing identities side by side. It offers the ability
to manage relationships between users and things with authorized access based on those relationships. Google's
IoT Core can be used alongside the ForgeRock Identity Platform if you want to add user and device relationships
to your IoT solution.

The goal of this integration is to prove the aforementioned concept. It uses an
[ICF Connector](https://backstage.forgerock.com/docs/idm/7.1/connector-reference/) to query device identities in
GCP IoT Core and synchronize and map them to things in the ForgeRock Platform. The integration is built on top of
[ForgeRock's ForgeOps CDK](https://backstage.forgerock.com/docs/forgeops/7/index-forgeops.html) with added
configuration for [ForgeRock IoT](https://backstage.forgerock.com/docs/iot/7.1) and the ICF Connector, integrated
into [ForgeRock Identity Management](https://backstage.forgerock.com/docs/idm/7.1).

#### Integration Components
![Components](docs/forgerock-gcp-integration.png)

The diagram illustrates how the different components interact with each other. The connector uses the ICF Framework
and the GCP IoT Core SDK to synchronize device identities that exist in the GCP IoT Core Device Registry to thing
identities in ForgeRock Directory Services.

Thing identities are stored alongside user identities in the ForgeRock Platform, which allows you to manage
relationships between users and things. These relationships can then be used to authorize access to devices or to the
device's resources.

#### Relationship Management
![](docs/device-management.png)

This diagram illustrates identity synchronization and device management.
 - An administrator creates a device in GCP IoT Core using the device manager.
 - Once created, the device identity is automatically synchronized to the ForgeRock Platform.
 - The administrator can then manage relationships between users and devices in the ForgeRock Platform or change the
  device configuration, and it will automatically be synchronized between ForgeRock and GCP.
 - A user may request access to a device or to a device's resources.
 - Access is authorized by the ForgeRock Platform based on the relationship that exists between the user and the device.
 
#### Configure Google Cloud Platform

To configure GCP for IoT, follow these steps:

1. Create or use an existing GCP project
1. Enable IoT Core
1. [Create](https://cloud.google.com/iot/docs/how-tos/devices#iot-core-create-registry) a device registry 
1. [Create](https://cloud.google.com/docs/authentication/production) a service account
1. Give the service account the [correct role](https://cloud.google.com/iam/docs/understanding-roles) - 
cloudiot.provisioner should be sufficient
1. Save the service credentials JSON to disk.

On creation of a GCP IoT Core connector, IDM will request the service account credentials,
along with the project id, region and registry id.
 
#### References
- [ICF Connector Developer's Guide](https://backstage.forgerock.com/docs/idm/7.1/connector-dev-guide/)
- [Google Cloud IoT Core documentation](https://cloud.google.com/iot/docs)
- [Cloud IoT Java API](https://developers.google.com/resources/api-libraries/documentation/cloudiot/v1/java/latest/com/google/api/services/cloudiot/v1/CloudIot.html)
- [Cloud IoT Java API examples](https://github.com/GoogleCloudPlatform/java-docs-samples/tree/master/iot/api-client/manager/src/main/java/com/example/cloud/iot/examples)