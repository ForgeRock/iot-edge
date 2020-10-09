#!/usr/bin/env bash
set -e

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


BASE_OVERLAY_DIR=$(PWD)/overlay
CUSTOM_OVERLAY_DIR=
DEPLOY_DIR=$(PWD)/tmp
PLATFORM_PASSWORD=$(openssl rand -base64 32)

if [ -n "$1" ]; then
  DEPLOY_DIR=$1
fi

if [ -n "$2" ]; then
  CUSTOM_OVERLAY_DIR=$2
fi

if [ -n "$3" ]; then
  PLATFORM_PASSWORD=$3
fi

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf "${DEPLOY_DIR}" && mkdir "$DEPLOY_DIR" && cd "$DEPLOY_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
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
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$DEPLOY_DIR"
if [ -n "$CUSTOM_OVERLAY_DIR" ]; then
  cp -rf  "$CUSTOM_OVERLAY_DIR"/* "$DEPLOY_DIR"
fi

echo "====================================================="
echo "Substitute platform password"
echo "====================================================="
sed -i '' "s/&{platform.password}/$PLATFORM_PASSWORD/g" "$DEPLOY_DIR/config/7.0/iot/am/config/services/realm/root/sunidentityrepositoryservice/1.0/organizationconfig/default/opendj.json"

echo "====================================================="
echo "Initialise 'iot' configuration"
echo "====================================================="
"$DEPLOY_DIR"/bin/config.sh init --profile iot --version 7.0
"$DEPLOY_DIR"/bin/config.sh init --profile iot --component ds --version 7.0

echo "====================================================="
echo "Configure global password"
echo "====================================================="
password_file="$DEPLOY_DIR/docker/forgeops-secrets/forgeops-secrets-image/config/OVERRIDE_ALL_PASSWORDS.txt"
touch "$password_file"
echo "$PLATFORM_PASSWORD" > "$password_file"

echo "====================================================="
echo "Clean out existing pods for 'iot' namespace"
echo "====================================================="
skaffold delete
"$DEPLOY_DIR"/bin/clean.sh

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "Create and install the certificate"
echo "====================================================="
if [ ! -f _wildcard.iam.example.com.pem ]; then
  mkcert "*.iam.example.com"
  mkcert -install
fi
kubectl delete secret sslcert
kubectl create secret tls sslcert --cert=_wildcard.iam.example.com.pem --key=_wildcard.iam.example.com-key.pem

echo "====================================================="
echo "URL: https://iot.iam.example.com/platform"
echo "Username: amadmin"
echo "Password: $PLATFORM_PASSWORD"
echo "====================================================="
