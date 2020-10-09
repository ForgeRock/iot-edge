# ForgeOps for Things

This directory contains resources for deploying Things with the ForgeRock Identity Platform to Kubernetes using ForgeOps.

### Get Started

Install the third party software by following the instructions in the
[ForgeOps docs](https://backstage.forgerock.com/docs/forgeops/7/devops-minikube-implementation-env.html#devops-implementation-env-sw).

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