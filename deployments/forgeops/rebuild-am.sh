#!/usr/bin/env bash
set -e

#
# Copyright 2022-2023 ForgeRock AS
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
CONFIG_PROFILE=cdk

if [[ -z "$NAMESPACE" || -z "$FQDN" || -z "$CLUSTER" || -z "$ZONE" || -z "$PROJECT" || -z "$CONTAINER_REGISTRY" ]]; then
  echo "NAMESPACE, FQDN, CLUSTER, ZONE, PROJECT and CONTAINER_REGISTRY variables must be set"
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

if [ -n "$3" ]; then
  PLUGIN_DIR=$3
  echo "Plugin directory: $PLUGIN_DIR"
fi

echo "====================================================="
echo "Environment variables"
echo "====================================================="
echo "PROJECT=$PROJECT"
echo "CLUSTER=$CLUSTER"
echo "ZONE=$ZONE"
echo "NAMESPACE=$NAMESPACE"
echo "FQDN=$FQDN"
echo "CONTAINER_REGISTRY=$CONTAINER_REGISTRY"

echo "====================================================="
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$FORGEOPS_DIR"
if [ -n "$CUSTOM_OVERLAY_DIR" ]; then
  cp -rf  "$CUSTOM_OVERLAY_DIR"/* "$FORGEOPS_DIR"
fi

echo "====================================================="
echo "Deploy AM"
echo "====================================================="

docker tag gcr.io/forgerock-io/am-cdk/docker-build:latest gcr.io/engineering-devops/iot-ft/am-cdk:latest
docker push gcr.io/engineering-devops/iot-ft/am-cdk:latest

cd "$FORGEOPS_DIR/bin"
./forgeops build am --config-profile "$CONFIG_PROFILE" --push-to "$CONTAINER_REGISTRY"
./forgeops delete am -y
./forgeops install am --cdk
