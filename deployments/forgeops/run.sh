#!/usr/bin/env bash
set -e

#
# Copyright 2020-2022 ForgeRock AS
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
FORGEOPS_DIR=$(PWD)/tmp/forgeops
SECRETS_IN_DIR=$(PWD)/secrets
SECRETS_OUT_DIR=$(PWD)/tmp/secrets
CONFIG_PROFILE=cdk
NAMESPACE=iot
FQDN=iot.iam.example.com

if [ -n "$1" ]; then
  CUSTOM_OVERLAY_DIR=$1
  echo "Custom overlay directory: $CUSTOM_OVERLAY_DIR"
fi

if [ -n "$2" ]; then
  PLATFORM_PASSWORD=$2
  echo "Overriding platform password: $PLATFORM_PASSWORD"
fi

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf "${FORGEOPS_DIR}" && mkdir "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
git checkout release/7.1.0

echo "====================================================="
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$FORGEOPS_DIR"
if [ -n "$CUSTOM_OVERLAY_DIR" ]; then
  cp -rf  "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"
fi
rm -rf "$SECRETS_OUT_DIR" && mkdir -p "$SECRETS_OUT_DIR"
cp -rf "$SECRETS_IN_DIR"/* "$SECRETS_OUT_DIR"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{FQDN}/$FQDN/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$SECRETS_OUT_DIR/iot-secrets.yaml"

echo "====================================================="
echo "Start and configure Minikube"
echo "====================================================="
minikube start --memory=12288 --cpus=3 --disk-size=40g --cni=true --vm=true --driver=virtualbox --bootstrapper kubeadm --kubernetes-version=stable
minikube addons enable ingress
"$FORGEOPS_DIR"/bin/secret-agent install

echo "====================================================="
echo "Create 'iot' namespace"
echo "====================================================="
set +e
kubectl create namespace iot
kubens iot
set -e

echo "====================================================="
echo "Use Minikube's built-in docker"
echo "====================================================="
eval $(minikube docker-env)
skaffold config set --kube-context minikube local-cluster true

echo "====================================================="
echo "Clean out existing pods for 'iot' namespace"
echo "====================================================="
skaffold delete

echo "====================================================="
echo "Apply IoT secrets"
echo "====================================================="
if [ -n "$PLATFORM_PASSWORD" ]; then
  kubectl delete secret am-env-secrets || true
  kubectl create secret generic am-env-secrets --from-literal=AM_PASSWORDS_AMADMIN_CLEAR=$PLATFORM_PASSWORD
fi
kubectl apply --filename $SECRETS_OUT_DIR/iot-secrets.yaml
kubectl create --filename $SECRETS_OUT_DIR/iot-secret-agent-configuration.yaml

echo "====================================================="
echo "Initialise '$CONFIG_PROFILE' configuration profile"
echo "====================================================="
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --version 7.0
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --component ds --version 7.0

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
# The very first time sslcert does not exist so the delete command will fail. The `||  true' stops the script exiting.
kubectl delete secret sslcert || true
kubectl create secret tls sslcert --cert=_wildcard.iam.example.com.pem --key=_wildcard.iam.example.com-key.pem

echo "====================================================="
echo "~~~ Platform login details ~~~"
$FORGEOPS_DIR/bin/print-secrets
echo "====================================================="
