#!/usr/bin/env bash

#
# Copyright 2020 ForgeRock AS
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

PLATFORM_PASSWORD=
if [ -n "$1" ]; then
  PLATFORM_PASSWORD=$1
fi

OVERLAY_DIR=$(PWD)/forgeops
DEPLOYMENT_DIR=$(PWD)/../../../deployments/forgeops

echo "====================================================="
echo "Build the connector"
echo "====================================================="
cd iot-hub-connector
mvn clean install
rm -rf ../forgeops/docker/7.0/idm/connectors && mkdir -p ../forgeops/docker/7.0/idm/connectors
cp target/azure-iot-hub-connector-0.1-SNAPSHOT.jar ../forgeops/docker/7.0/idm/connectors/azure-iot-hub-connector-0.1-SNAPSHOT.jar

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$DEPLOYMENT_DIR"
./run.sh "$OVERLAY_DIR" "$PLATFORM_PASSWORD"
