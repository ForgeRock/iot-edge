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

CUSTOM_NODE_DIR=$(PWD)/auth-nodes
PLUGIN_DIR=$(PWD)/forgeops/tmp/am
FORGEOPS_DIR=$(PWD)/../../../deployments/forgeops
CUSTOM_OVERLAY_DIR=$(PWD)/forgeops/overlay

echo "====================================================="
echo "Build the custom node"
echo "====================================================="
cd "$CUSTOM_NODE_DIR"
./build.sh "$PLUGIN_DIR"

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$FORGEOPS_DIR"
./deploy.sh "$CUSTOM_OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn "$PLUGIN_DIR"