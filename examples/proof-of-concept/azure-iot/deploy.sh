#!/usr/bin/env bash
set -e

#
# Copyright 2023 ForgeRock AS
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
CONNECTOR_DIR=$POC_DIR/iot-hub-connector
CUSTOM_OVERLAY_DIR=$POC_DIR/forgeops/overlay
PLUGIN_DIR=$CUSTOM_OVERLAY_DIR/docker/idm/tmp

echo "====================================================="
echo "Clone IoT Edge directory"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.4.0

echo "====================================================="
echo "Build the connector"
echo "====================================================="
cd "$CONNECTOR_DIR"
./build.sh "$PLUGIN_DIR"

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$FORGEOPS_DIR"
./deploy.sh "$CUSTOM_OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn

