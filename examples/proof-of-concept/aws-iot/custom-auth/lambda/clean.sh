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

AWS_FUNCTION_NAME="iot-custom-authorize-handler"
AWS_ROLE_NAME="iot-custom-authorize-handler-execution-role"
AWS_AUTHORIZER_NAME="iot-custom-authorizer"

# Delete the execution role
aws iam detach-role-policy \
  --role-name ${AWS_ROLE_NAME} \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role \
  --role-name ${AWS_ROLE_NAME}

# Delete the lambda
aws lambda delete-function \
  --function-name ${AWS_FUNCTION_NAME}

# Delete the custom authorizer
aws iot update-authorizer \
  --authorizer-name ${AWS_AUTHORIZER_NAME} \
  --status INACTIVE

aws iot delete-authorizer \
  --authorizer-name ${AWS_AUTHORIZER_NAME}
