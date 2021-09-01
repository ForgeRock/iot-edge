# Standard OAuth 2.0 API with ForgeRock IoT Solution

![Standard API Flow](docs/standard-oauth-api-flow.png)

## Deploy and Run

*This example requires you to have a high level of familiarity with ForgeOps and the ForgeRock IoT Solution. Contact
ForgeRock for a demonstration of the solution.*

Follow the instructions in the [ForgeOps docs](https://backstage.forgerock.com/docs/forgeops/7.1/cdk/cloud/setup/gke/gke-setup.html)
to prepare your environment. In the `deploy.sh` script, change the values of the `CLUSTER`, `ZONE` and `PROJECT` variables
to the values in your own environment.

Replace the namespace and FQDN in the following instructions.

(Re)Deploy the Things CDK to GKE:
```
./deploy.sh my-namespace dev.example.com
```

Request the Access Token:
```
./access-token.sh dev.example.com
```
