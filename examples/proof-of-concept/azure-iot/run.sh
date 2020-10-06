#!/usr/bin/env bash

#
# Copyright 2020 ForgeRock AS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf tmp && mkdir tmp
git clone https://github.com/ForgeRock/forgeops.git tmp/forgeops
cd tmp/forgeops
git checkout tags/2020.08.07-ZucchiniRicotta.1

echo "====================================================="
echo "Build and add the connector"
echo "====================================================="
cd ../../iot-hub-connector
mvn clean install
mkdir -p ../tmp/forgeops/docker/7.0/idm/connectors
cp target/azure-iot-hub-connector-0.1-SNAPSHOT.jar ../tmp/forgeops/docker/7.0/idm/connectors/azure-iot-hub-connector-0.1-SNAPSHOT.jar
cd ../tmp/forgeops

echo "====================================================="
echo "Start and configure Minikube"
echo "====================================================="
minikube start --memory=12288 --cpus=3 --disk-size=40g --vm-driver=virtualbox --bootstrapper kubeadm --kubernetes-version=1.17.4
minikube addons enable ingress
minikube ssh sudo ip link set docker0 promisc on

echo "====================================================="
echo "Create 'iot' namespace"
echo "====================================================="
kubectl create namespace iot
kubens iot

echo "====================================================="
echo "Use Minikube's built-in docker"
echo "====================================================="
eval $(minikube docker-env)
skaffold config set --kube-context minikube local-cluster true

echo "====================================================="
echo "Overlay and initialise 'iot' configuration"
echo "====================================================="
cp -rf ../../forgeops/config/* config
cd bin
./config.sh init --profile iot --version 7.0
./config.sh init --profile iot --component ds --version 7.0
cd ../
# This must be done after initialisation otherwise it will be deleted
cp -rf ../../forgeops/docker/* docker
cp -rf ../../forgeops/kustomize/* kustomize

echo "====================================================="
echo "Clean out existing pods for 'iot' namespace"
echo "====================================================="
skaffold delete
cd bin && ./clean.sh && cd ../

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "Create and install the certificate"
echo "====================================================="
cd ../../
if [ ! -f _wildcard.iam.example.com.pem ]; then
  mkcert "*.iam.example.com"
  mkcert -install
fi
kubectl delete secret sslcert
kubectl create secret tls sslcert --cert=_wildcard.iam.example.com.pem --key=_wildcard.iam.example.com-key.pem
