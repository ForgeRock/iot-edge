#!/usr/bin/env bash
set -e

#
# Copyright 2021 ForgeRock AS
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

FORGEOPS_DIR=$(PWD)/tmp/forgeops
IOT_EDGE_DIR=$(PWD)/tmp/iot-edge
BASE_OVERLAY_DIR=$IOT_EDGE_DIR/deployments/forgeops/overlay
CUSTOM_OVERLAY_DIR=$(PWD)/forgeops/overlay
PLATFORM_PASSWORD=
SECRETS_DIR=$(PWD)/forgeops/secrets
CONFIG_PROFILE=cdk
NAMESPACE=
FQDN=
CLUSTER=eng-shared-1
ZONE=us-east1
PROJECT=engineering-devops

if [ -n "$1" ]; then
  NAMESPACE=$1
  echo "Setting namespace: $NAMESPACE"
fi
if [ -n "$2" ]; then
  FQDN=$2
  echo "Setting FQDN: $FQDN"
fi
if [ -n "$3" ]; then
  PLATFORM_PASSWORD=$3
  echo "Overriding platform password: $PLATFORM_PASSWORD"
fi

echo "====================================================="
echo "Clone Things and ForgeOps"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.1.0
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
git checkout release/7.1.0

echo "====================================================="
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$FORGEOPS_DIR"
cp -rf "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"
cp -rf "$SECRETS_DIR"/* "$IOT_EDGE_DIR/deployments/forgeops/secrets"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{FQDN}/$FQDN/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{NAMESPACE}/$NAMESPACE/g" "$IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secrets.yaml"

echo "====================================================="
echo "Create '$NAMESPACE' namespace"
echo "====================================================="
kubectl create namespace $NAMESPACE || true
kubens $NAMESPACE

echo "====================================================="
echo "Configure Skaffold to use default repo"
echo "====================================================="
skaffold config set default-repo gcr.io/$PROJECT -k gke_$PROJECT_$ZONE_$CLUSTER

echo "====================================================="
echo "Clean out existing pods for '$NAMESPACE' namespace"
echo "====================================================="
skaffold delete

echo "====================================================="
echo "Initialise '$CONFIG_PROFILE' configuration profile"
echo "====================================================="
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --version 7.0
"$FORGEOPS_DIR"/bin/config.sh init --profile $CONFIG_PROFILE --component ds --version 7.0

echo "====================================================="
echo "Apply IoT secrets"
echo "====================================================="
if [ -n "$PLATFORM_PASSWORD" ]; then
  kubectl delete secret am-env-secrets || true
  kubectl create secret generic am-env-secrets --from-literal=AM_PASSWORDS_AMADMIN_CLEAR=$PLATFORM_PASSWORD
fi
kubectl apply --filename $IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secrets.yaml
kubectl create --filename $IOT_EDGE_DIR/deployments/forgeops/secrets/iot-secret-agent-configuration.yaml

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "~~~ Platform login details ~~~"
echo "URL: https://$FQDN/platform"
echo "Username: amadmin"
echo "Password: $($FORGEOPS_DIR/bin/print-secrets amadmin)"
echo "DS Password: $($FORGEOPS_DIR/bin/print-secrets dsadmin)"
echo "====================================================="
