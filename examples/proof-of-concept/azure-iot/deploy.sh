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

CONNECTOR_DIR=$(PWD)/iot-hub-connector
PLUGIN_DIR=$(PWD)/forgeops/tmp/idm
DEPLOYMENT_DIR=$(PWD)/../../../deployments/forgeops
OVERLAY_DIR=$(PWD)/forgeops/overlay

echo "====================================================="
echo "Build the connector"
echo "====================================================="
cd "$CONNECTOR_DIR"
./build.sh "$PLUGIN_DIR"

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$DEPLOYMENT_DIR"
./deploy.sh "$OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn "$PLUGIN_DIR"

