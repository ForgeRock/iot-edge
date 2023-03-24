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

PLUGIN_DIR=$(PWD)/../forgeops/tmp/idm
AWS_REGISTRY_MANAGEMENT_USER="iot-registry-management-user"
AWS_THING_NAME="f971a95b-2fc6-4ce2-aed6-84f8c6cf6b05"

# Build the connector
./build.sh "$PLUGIN_DIR"

# Create the AWS IoT registry management user if it does not exist yet
users=$(aws iam list-users --query "Users[?UserName == '${AWS_REGISTRY_MANAGEMENT_USER}']")
if [ "${users}" == "[]" ]; then
  echo "Creating IoT management user [$AWS_REGISTRY_MANAGEMENT_USER]"
  aws iam create-user \
    --user-name ${AWS_REGISTRY_MANAGEMENT_USER}
  aws iam create-access-key \
    --user-name ${AWS_REGISTRY_MANAGEMENT_USER} > iot-access-key.secret
  aws iam attach-user-policy \
    --user-name ${AWS_REGISTRY_MANAGEMENT_USER} \
    --policy-arn arn:aws:iam::aws:policy/AWSIoTFullAccess
fi

# Create a thing with a UUID as the name if it does not exist yet
things=$(aws iot list-things --query "things[?thingName == '${AWS_THING_NAME}']")
if [ "${things}" == "[]" ]; then
  echo "Creating IoT thing [$AWS_THING_NAME]"
  aws iot create-thing \
    --thing-name ${AWS_THING_NAME} \
    --attribute-payload "attributes={host=localhost,port=5154},merge=true"
fi
