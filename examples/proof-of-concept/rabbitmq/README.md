## RabbitMQ Proof of Concept

The ForgeRock Platform can provide authentication and authorisation for third party products, 
removing the need for these products to internally manage IoT identities.

This PoC illustrates how access control within the [RabbitMQ](http://www.rabbitmq.com) message broker can be delegated to the ForgeRock platform,
ensuring that only authenticated things can publish or subscribe to authorised topics.
The PoC is built on top of
[ForgeRock's ForgeOps CDK](https://backstage.forgerock.com/docs/forgeops/7.3/index.html) with added
configuration for [ForgeRock IoT](https://backstage.forgerock.com/docs/iot/7.2).
RabbitMQ is configured to use the [OAuth 2.0 (JWT) Token Authorisation Backend](https://github.com/rabbitmq/rabbitmq-auth-backend-oauth2) 
which ships with RabbitMQ since version 3.8. 
The configuration changes can be summarised as:

* ForgeRock Access Manager (AM) can issue client-based OAuth 2.0 access tokens with RabbitMQ specific 
[scopes](https://github.com/rabbitmq/rabbitmq-auth-backend-oauth2#scope-to-permission-translation).
* RabbitMQ uses the OAuth 2.0 (JWT) Token Authorisation Backend for access control 
and is provided with the following information from AM:
    * The name of the OAuth 2.0 client associated with things.
    * The public key of the private asymmetric key used to sign the JWT.

#### Integrated Components

![Components](docs/rabbitmq-integration.png)

The diagram illustrates how the different components interact with each other.

#### Authentication and Authorisation flow

![AuthX](docs/rabbitmq-oauth2-authx.png)

The diagram shows a example authentication and authorisation flow.
The Auth 2.0 access token can be reused until it expires, 
when the device would have to re-authenticate with AM to retrieve another token. 

#### Thing Publisher Example
In a terminal, navigate to this directory and call the run script:

```
./deploy.sh
```

This will run an IoT enabled CDK and put up a RabbitMQ server and a things container. 

Run the Thing Publisher example by running:

```
docker exec -it things go run rabbit-demo/thing-pub
```

The messages from the Thing can be read from the terminal by using a MQTT command line client and the `admin` user:

* username: `admin`
* password: `password`

For example:
```
mosquitto_sub -u admin -P password -t test
```
