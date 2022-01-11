#!/usr/bin/env bash
set -e

#
# Copyright 2022 ForgeRock AS
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
BASE_OVERLAY_DIR=$(PWD)/overlay
SECRETS_IN_DIR=$(PWD)/secrets
SECRETS_OUT_DIR=$(PWD)/tmp/secrets
CONFIG_PROFILE=cdk

if [[ -z "$NAMESPACE" || -z "$FQDN" || -z "$CLUSTER" || -z "$ZONE" || -z "$PROJECT" ]]; then
  echo "NAMESPACE, FQDN, CLUSTER, ZONE and PROJECT variables must be set"
exit 1
fi

if [ -n "$1" ]; then
  CUSTOM_OVERLAY_DIR=$1
  echo "Custom overlay directory: $CUSTOM_OVERLAY_DIR"
fi

if [ -n "$2" ]; then
  PLATFORM_PASSWORD=$2
  echo "Overriding platform password: $PLATFORM_PASSWORD"
fi

echo "====================================================="
echo "Environment variables"
echo "====================================================="
echo "PROJECT=$PROJECT"
echo "CLUSTER=$CLUSTER"
echo "ZONE=$ZONE"
echo "NAMESPACE=$NAMESPACE"
echo "FQDN=$FQDN"

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
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
echo "Create '$NAMESPACE' namespace"
echo "====================================================="
set +e
kubectl create namespace $NAMESPACE
kubens $NAMESPACE
set -e

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
kubectl apply --filename $SECRETS_OUT_DIR/iot-secrets.yaml
kubectl create --filename $SECRETS_OUT_DIR/iot-secret-agent-configuration.yaml

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "~~~ Platform login details ~~~"
$FORGEOPS_DIR/bin/print-secrets
echo "====================================================="
