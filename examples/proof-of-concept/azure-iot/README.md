## Azure IoT Integration

The ForgeRock Identity Platform allows you to manage user and thing identities side by side. It offers the ability
to manage relationships between users and things with authorized access based on those relationships. Microsoft's
Azure IoT can be used alongside the ForgeRock Identity Platform if you want to add user and device relationships
to your IoT solution.

The goal of this integration is to prove the aforementioned concept. It uses an
[ICF Connector](https://backstage.forgerock.com/docs/openicf/latest/index.html) to query device identities in
Azure IoT Hub and synchronize and map them to things in the ForgeRock Platform. The integration is built on top of
[ForgeRock's ForgeOps CDK](https://backstage.forgerock.com/docs/forgeops/7.4/index.html) with added
configuration for [ForgeRock IoT](https://backstage.forgerock.com/docs/iot/7.4) and the ICF Connector, integrated
into [ForgeRock Identity Management](https://backstage.forgerock.com/docs/idm/7.4/index.html).

#### Integration Components
![Components](docs/forgerock-azure-integration.png)

The diagram illustrates how the different components interact with each other. The connector uses the ICF Framework
and the Azure IoT SDK to synchronize device identities that exist in the Azure IoT Hub Identity Registry to thing
identities in ForgeRock Directory Services.

Thing identities are stored alongside user identities in the ForgeRock Platform, which allows you to manage
relationships between users and things. These relationships can then be used to authorize access to devices or to the
device's resources.

#### Relationship Management
![](docs/device-management.png)

This diagram illustrates identity synchronization and device management.
 - A device is either dynamically provisioned to the Azure IoT Hub, or manually added by an administrator.
 - Once provisioned, the device identity is automatically synchronized to the ForgeRock Platform.
 - The administrator can then manage relationships between users and devices in the ForgeRock Platform or change the
  device configuration, and it will automatically be synchronized between ForgeRock and Azure.
 - A user may request access to a device or to a device's resources.
 - Access is authorized by the ForgeRock Platform based on the relationship that exists between the user and the device.

### Run the ForgeRock Platform

*This example requires you to have a high level of familiarity with ForgeOps and the ForgeRock IoT Solution. Contact
ForgeRock for a demonstration of the solution.*

Follow the ForgeOps documentation to install the
[third party software](https://backstage.forgerock.com/docs/forgeops/7.4/cdk/cloud/setup/gke/sw.html) and
[obtain the cluster details](https://backstage.forgerock.com/docs/forgeops/7.4/cdk/cloud/setup/gke/clusterinfo.html).

Set the following environment variables:
```
export PROJECT=<The name of the Google Cloud project that contains the cluster>
export CLUSTER=<The cluster name>
export ZONE=<The Google Cloud zone in which the cluster resides>
export NAMESPACE=<The namespace to use in your cluster>
export FQDN=<The fully qualified domain name of your deployment>
export CONTAINER_REGISTRY=<The default container registry>
```

After installing the Google Cloud SDK, authenticate the SDK:
```
gcloud auth login
```

Deploy the Things CDK to GKE:
```
./deploy.sh
```

### Using the Connector in IDM
To configure the connector, you will need to obtain the primary connection string from your Azure IoT Hub.

The **Connector Name** field *must* be set to *AzureIoT*, as this is case-sensitive.

The current configuration only accepts 36-byte UUIDs for identities, therefore any device ID stored in 
the Azure IoT Hub Identity Registry must follow this format.

#### References
- [ICF Connector Developer's Guide](https://backstage.forgerock.com/docs/openicf/latest/connector-dev-guide)
- [Get started with device twins](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-java-java-twin-getstarted)
- [IoT Hub Query Language](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-query-language)
- [IoT Hub Identity Registry](https://docs.microsoft.com/en-us/azure/iot-hub/iot-hub-devguide-identity-registry)