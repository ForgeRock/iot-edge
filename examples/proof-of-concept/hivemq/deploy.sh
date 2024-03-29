#!/usr/bin/env bash
set -e

#
# Copyright 2021-2023 ForgeRock AS
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
POC_TMP_DIR=$POC_DIR/tmp
IOT_EDGE_DIR=$POC_TMP_DIR/iot-edge
HIVEMQ_DIR=$POC_TMP_DIR/hivemq
HIVEMQ_CONFIG=$POC_DIR/broker
HIVEMQ_TAG=fr-hivemq
FORGEOPS_DIR=$IOT_EDGE_DIR/deployments/forgeops
CUSTOM_OVERLAY_DIR=$POC_DIR/forgeops/overlay

echo "====================================================="
echo "Clone IoT Edge directory"
echo "====================================================="
rm -rf "$IOT_EDGE_DIR" && mkdir -p "$IOT_EDGE_DIR" && cd "$IOT_EDGE_DIR"
git clone https://github.com/ForgeRock/iot-edge.git .
git checkout release/v7.4.0

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$FORGEOPS_DIR"
./deploy.sh "$CUSTOM_OVERLAY_DIR" 6KZjOxJU1xHGWHI0hrQT24Fn

echo "====================================================="
echo "Building HiveMQ"
echo "====================================================="
rm -rf "$HIVEMQ_DIR" && mkdir -p "$HIVEMQ_DIR" && cd "$HIVEMQ_DIR"
cp -rf "$HIVEMQ_CONFIG"/* "$HIVEMQ_DIR"
sed -i '' "s/&{FQDN}/$FQDN/g" "$HIVEMQ_DIR/enterprise-security-extension.xml"
docker build -t "$HIVEMQ_TAG" .

echo "====================================================="
echo "~~~ HiveMQ details ~~~"
echo "Run Broker: docker run -it --rm -p 8080:8080 -p 1883:1883 $HIVEMQ_TAG"
echo "Run Client: cd things && go run ./cmd/mqtt-client -fqdn $FQDN"
echo "====================================================="
