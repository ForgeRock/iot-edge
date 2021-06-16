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

IOT_EDGE_DIR=$(PWD)/tmp/iot-edge
FORGEOPS_DIR=$IOT_EDGE_DIR/deployments/forgeops
CUSTOM_OVERLAY_DIR=$(PWD)/forgeops
PLATFORM_PASSWORD=

if [ -n "$1" ]; then
  PLATFORM_PASSWORD=$1
  echo "Overriding platform password: $PLATFORM_PASSWORD"
fi

echo "====================================================="
echo "Clone IoT Edge"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.1.0

echo "====================================================="
echo "Run the platform"
echo "====================================================="
cd $FORGEOPS_DIR
./run.sh $CUSTOM_OVERLAY_DIR $PLATFORM_PASSWORD