# ForgeOps for IoT

This directory contains resources for deploying Things with the ForgeRock Identity Platform to Kubernetes using ForgeOps.

### Get Started

Install the third party software by following the instructions in the
[ForgeOps docs](https://backstage.forgerock.com/docs/forgeops/7/devops-minikube-implementation-env.html#devops-implementation-env-sw).
Additionally, install [mkcert](https://github.com/FiloSottile/mkcert) for making locally-trusted development certificates.

Clone this repo:
```
git clone https://github.com/ForgeRock/iot-edge.git
cd iot-edge/deployments/forgeops
```

Start the platform:
```
./run.sh
```

In a new terminal, run `minikube ip` and map the output from the command to `iot.iam.example.com` in your hosts file:
```
echo "192.168.99.100 iot.iam.example.com" >> /etc/hosts
```

A new platform password will be generated and printed to the console:
```
=====================================================
URL: https://iot.iam.example.com/platform
Username: amadmin
Password: jvswdgsoe0bdbzf4r0kgaa00
=====================================================
```

### Run Functional Tests

The functional test framework, Anvil, can be run against the ForgeOps IoT Platform to verify that all the IoT SDK and
IoT Gateway features work correctly.

Start the platform before running the tests:
```
./run.sh $(PWD)/../../tests/iotsdk/testdata/forgeops 1zeAyq0jCGV8jpVaesXS3q3dKm8qWiI6dZ1GBS2M1Ds0
```

Run the functional tests:
```
cd ../../
./run.sh anvil -deployment=platform -url=https://iot.iam.example.com/am -password=1zeAyq0jCGV8jpVaesXS3q3dKm8qWiI6dZ1GBS2M1Ds0
```
