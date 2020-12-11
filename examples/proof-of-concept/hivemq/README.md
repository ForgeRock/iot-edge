## HiveMQ Integration

The ForgeRock Identity Platform can issue OAuth 2.0 access tokens for authentication and authorization. The
[HiveMQ](https://www.hivemq.com/) Enterprise Security Extension (ESE) supports JSON Web Tokens (JWT) and allows
integration with OAuth 2.0 authorization servers for client authentication and authorization.

The goal of this integration is to prove the aforementioned concept. It is built on top of
[ForgeRock's ForgeOps CDK](https://backstage.forgerock.com/docs/forgeops/7/index-forgeops.html) with added
configuration for [ForgeRock IoT](https://backstage.forgerock.com/docs/things/7). It uses the public
[HiveMQ Docker image](https://www.hivemq.com/docs/hivemq/4.4/user-guide/docker.html), which is configured to use the
[Enterprise Security Extension](https://www.hivemq.com/docs/ese/4.4/enterprise-security-extension/ese-getting-started.html).

#### Integration Components

![Components](docs/hivemq-integration.png)

The diagram illustrates how the different components interact with each other. The device client application
communicates directly with the ForgeRock Platform and HiveMQ in order to authenticate, authorize and publish data.

#### Authentication and Authorization

![AuthX](docs/hivemq-oauth2-authx.png)

The diagram shows an example authentication and authorization flow.
 - Using the IoT SDK, the device registers and authenticates itself with the ForgeRock Platform.
 - It then requests an OAuth 2.0 access token with the `publish` scope.
 - The device then connects to HiveMQ using MQTT, with the access token as the connection password.
 - HiveMQ ESE will verify the access token signature and scope and authenticate the device. The access token is verified
   locally with the JSON web keys downloaded from the ForgeRock Platform. Additional access token verification can be
   done using the ForgeRock Platform, see the
   [HiveMQ ESE documentation](https://www.hivemq.com/docs/ese/4.4/enterprise-security-extension/ese.html#jwt).
  