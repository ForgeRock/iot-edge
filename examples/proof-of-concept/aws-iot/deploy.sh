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
POC_DIR=$(PWD)
IOT_EDGE_DIR=$POC_DIR/tmp/iot-edge
FORGEOPS_DIR=$IOT_EDGE_DIR/deployments/forgeops
LAMBDA_DIR=$(PWD)/custom-auth/lambda

echo "====================================================="
echo "Clone IoT Edge directory"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.4.0

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
  CONNECTOR_DIR=$POC_DIR/scriptedrest-connector
else
  CONNECTOR_DIR=$POC_DIR/registry-connector
fi

CUSTOM_OVERLAY_DIR=$CONNECTOR_DIR/forgeops/overlay
PLUGIN_DIR=$CONNECTOR_DIR/../forgeops/tmp/idm

cd "$CONNECTOR_DIR"
./deploy.sh

echo "====================================================="
echo "Deploy and configure AWS custom authorizer function"
echo "====================================================="
cd "$LAMBDA_DIR"
./deploy.sh

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$FORGEOPS_DIR"
./deploy.sh "$CUSTOM_OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn "$PLUGIN_DIR"
