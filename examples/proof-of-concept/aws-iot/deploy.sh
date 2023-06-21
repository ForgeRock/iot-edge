#!/usr/bin/env bash
set -e

#
# Copyright 2020-2023 ForgeRock AS
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

LAMBDA_DIR=$(PWD)/custom-auth/lambda
DEPLOYMENT_DIR=$(PWD)/../../../deployments/forgeops
FORGEOPS_DIR=$DEPLOYMENT_DIR/tmp/forgeops

if [ -n "$1" ]; then
  CONNECTOR_TYPE=$1
  echo "Connector specified: $CONNECTOR_TYPE"
else
  echo "No connector specified, defaulting to Java connector..."
fi

echo "====================================================="
echo "Build and deploy the connector"
echo "====================================================="
if [ "$CONNECTOR_TYPE" = "scriptedrest" ]; then
  CONNECTOR_DIR=$(PWD)/scriptedrest-connector
else
  CONNECTOR_DIR=$(PWD)/registry-connector
fi

OVERLAY_DIR=$CONNECTOR_DIR/forgeops/overlay
PLUGIN_DIR=$CONNECTOR_DIR/../forgeops/tmp/idm

cd "$CONNECTOR_DIR"
./deploy.sh

if [ "$CONNECTOR_TYPE" != "scriptedrest" ]; then
  echo "====================================================="
  echo "Deploy and configure AWS custom authorizer function"
  echo "====================================================="
  cd "$LAMBDA_DIR"
  ./deploy.sh
fi

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$DEPLOYMENT_DIR"
./deploy.sh "$OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn "$PLUGIN_DIR"

echo "====================================================="
echo "Build new IDM image and redeploy"
echo "====================================================="
cd "$FORGEOPS_DIR"
./bin/forgeops build idm --config-profile cdk --default-repo "$CONTAINER_REGISTRY"
./bin/forgeops delete idm
./bin/forgeops install idm --cdk
