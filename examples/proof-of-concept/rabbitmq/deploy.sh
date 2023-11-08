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
IOT_EDGE_DIR=$POC_DIR/tmp/iot-edge
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

printf "\nWaiting for AM to start up"
count=10
while [[ count -gt 0 ]]; do
  sleep 2 && printf "."
  ((count--))
  response=$(curl --write-out %{http_code} --silent --connect-timeout 5 --output /dev/null "${AM_URL}"/json/serverinfo/* )
  if (( response == 200 )); then
    printf "\nAM is ready to use.\n"
    ready="true"
    break
  fi
done

if [[ $ready != "true" ]]; then
  echo "AM did not respond with status 200 within expected time."
  exit 1
fi

echo "====================================================="
echo "Build and run the things image"
echo "====================================================="
cd "$POC_DIR"
docker compose up --build
