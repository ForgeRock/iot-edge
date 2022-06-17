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
SCRIPTS_DIR=$(PWD)/scripts
BASE_OVERLAY_DIR=$(PWD)/overlay-poc
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
echo "Configure GCP SDK"
echo "====================================================="
gcloud container clusters get-credentials $CLUSTER --zone $ZONE --project $PROJECT

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
git checkout release/7.2.0

echo "====================================================="
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$FORGEOPS_DIR"
if [ -n "$CUSTOM_OVERLAY_DIR" ]; then
  cp -rf  "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"
fi

echo "====================================================="
echo "Create '$NAMESPACE' namespace"
echo "====================================================="
kubectl create namespace $NAMESPACE || true
kubens $NAMESPACE

echo "====================================================="
echo "Apply IoT secrets"
echo "====================================================="
if [ -n "$PLATFORM_PASSWORD" ]; then
  kubectl create secret generic am-env-secrets --from-literal=AM_PASSWORDS_AMADMIN_CLEAR=$PLATFORM_PASSWORD || true
fi

echo "====================================================="
echo "Building AM and IDM"
echo "====================================================="
cd $FORGEOPS_DIR/bin
./forgeops build am --config-profile $CONFIG_PROFILE
./forgeops build idm --config-profile $CONFIG_PROFILE

echo "====================================================="
echo "Installing the Platform"
echo "====================================================="
./forgeops install --cdk --fqdn $FQDN

echo "====================================================="
echo "Applying custom DS schema"
echo "====================================================="
kubectl cp $SCRIPTS_DIR/apply_schema.sh ds-idrepo-0:/tmp
kubectl exec ds-idrepo-0 -- /bin/bash -c "/tmp/apply_schema.sh"
