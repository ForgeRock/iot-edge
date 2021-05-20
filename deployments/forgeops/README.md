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
