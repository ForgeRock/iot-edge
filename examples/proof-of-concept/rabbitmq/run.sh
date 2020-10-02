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

function run_cdk() {
  echo "====================================================="
  echo "Clone ForgeOps"
  echo "====================================================="
  cd forgeops
  rm -rf tmp && mkdir tmp
  git clone https://github.com/ForgeRock/forgeops.git tmp
  cd tmp
  git checkout tags/2020.08.07-ZucchiniRicotta.1

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
  cp -rf ../config/* config
  cd bin
  ./config.sh init --profile iot --version 7.0
  ./config.sh init --profile iot --component ds --version 7.0
  cd ../
  # This must be done after initialisation otherwise it will be deleted
  cp -rf ../docker/* docker
  cp -rf ../kustomize/* kustomize

  echo "====================================================="
  echo "Clean out existing pods for 'iot' namespace"
  echo "====================================================="
  skaffold delete
  cd bin && ./clean.sh && cd ../

  echo "====================================================="
  echo "Run the platform"
  echo "====================================================="
  skaffold run
  cd ../../
}

run_cdk

echo "====================================================="
echo "Build and run the things image"
echo "====================================================="
AM_IP_ADDRESS=$(minikube ip) docker-compose -f docker-compose.yml  up -d --build
