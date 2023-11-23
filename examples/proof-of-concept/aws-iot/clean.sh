#!/usr/bin/env bash

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
FORGEOPS_DIR=$POC_DIR/tmp/iot-edge/deployments/forgeops

if [ -n "$1" ]; then
  CONNECTOR_TYPE=$1
  echo "Connector specified: $CONNECTOR_TYPE"
else
  echo "No connector specified, defaulting to Java connector..."
fi

echo "====================================================="
echo "Delete all the AWS deployed components"
echo "====================================================="
if [ "$CONNECTOR_TYPE" != "scriptedrest" ]; then
  cd "$POC_DIR/custom-auth/lambda"
  ./clean.sh
  cd "$POC_DIR/registry-connector"
  ./clean.sh
else
  cd "$POC_DIR/scriptedrest-connector"
  ./clean.sh
fi

echo "====================================================="
echo "Delete all the GKE deployed components"
echo "====================================================="
rm -rf "$POC_DIR/forgeops/tmp"
cd "$FORGEOPS_DIR"
./clean.sh
