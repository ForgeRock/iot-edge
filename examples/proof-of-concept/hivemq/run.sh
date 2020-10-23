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

POC_DIR=$(PWD)
OVERLAY_DIR=$POC_DIR/forgeops
DEPLOYMENT_DIR=$POC_DIR/../../../deployments/forgeops

echo "====================================================="
echo "Run ForgeOps CDK"
echo "====================================================="
cd "$DEPLOYMENT_DIR"
./run.sh "$OVERLAY_DIR" "$PLATFORM_PASSWORD"

echo "====================================================="
echo "Build and run the mqtt broker and client image"
echo "====================================================="
rm -rf "$POC_DIR"/mqtt-broker/tmp && mkdir "$POC_DIR"/mqtt-broker/tmp
rm -rf "$POC_DIR"/mqtt-client/tmp && mkdir "$POC_DIR"/mqtt-client/tmp
cp "$DEPLOYMENT_DIR"/tmp/_wildcard.iam.example.com* "$POC_DIR"/mqtt-broker/tmp/
cp "$DEPLOYMENT_DIR"/tmp/_wildcard.iam.example.com* "$POC_DIR"/mqtt-client/tmp/
cd "$POC_DIR"
AM_IP_ADDRESS=$(minikube ip) docker-compose up -d --build

# Attach to the broker
docker attach hivemq

# Run the client
#docker exec -it mqtt-client bash -c mqtt-client
