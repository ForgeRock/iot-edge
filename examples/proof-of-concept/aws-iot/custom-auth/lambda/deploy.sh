#!/usr/bin/env bash
set -e

#
# Copyright 2019-2023 ForgeRock AS
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

POC_DIR=$(PWD)/../../
AWS_FUNCTION_NAME="iot-custom-authorize-handler"
AWS_ROLE_NAME="iot-custom-authorize-handler-execution-role"
AWS_AUTHORIZER_NAME="iot-custom-authorizer"
AWS_TOKEN_HEADER_NAME="X-Token-Header"

# Build the lambda before deploying it
./build.sh

# Create the AWS Lambda Execution Role if it does not exist yet
roles=$(aws iam list-roles --query "Roles[?RoleName == '${AWS_ROLE_NAME}']")
if [ "${roles}" == "[]" ]; then
  echo "Creating execution role..."
  aws iam create-role \
    --role-name ${AWS_ROLE_NAME} \
    --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'

fi
aws iam attach-role-policy \
  --role-name ${AWS_ROLE_NAME} \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Give the role some time to settle
sleep 5

# Create AWS Lambda authorize handler
cd bin
functions=$(aws lambda list-functions)
if [[ ${functions} =~ ${AWS_FUNCTION_NAME} ]]; then
  echo "Updating lambda..."
  aws lambda update-function-code \
      --function-name ${AWS_FUNCTION_NAME} \
      --zip-file fileb://handler.zip
else
  echo "Creating lambda..."
  aws lambda create-function \
    --function-name ${AWS_FUNCTION_NAME} \
    --memory 128 \
    --role arn:aws:iam::${AWS_ACCOUNT_ID}:role/${AWS_ROLE_NAME} \
    --runtime go1.x \
    --zip-file fileb://handler.zip \
    --handler authhandler

  # Add the environment variables required by the Lambda
  aws lambda update-function-configuration \
      --function-name ${AWS_FUNCTION_NAME} \
      --environment Variables={AWS_PUBLISH_RESOURCE="arn:aws:iot:${AWS_REGION}:${AWS_ACCOUNT_ID}:topic/customauthtesting"}

  # Add Lambda invocation permissions
  aws lambda add-permission \
      --function-name ${AWS_FUNCTION_NAME} \
      --principal iot.amazonaws.com \
      --source-arn arn:aws:iot:${AWS_REGION}:${AWS_ACCOUNT_ID}:authorizer/${AWS_AUTHORIZER_NAME} \
      --statement-id autherizer-statement \
      --action "lambda:InvokeFunction"
fi
cd - &>/dev/null

# Create custom authorizer and associate it with Lambda
device_public_key=$(cat $POC_DIR/custom-auth/keys/device-public.pem)
authorizers=$(aws iot list-authorizers)
if [[ ${authorizers} =~ ${AWS_AUTHORIZER_NAME} ]]; then
  echo "Updating authorizer..."
  aws iot update-authorizer \
      --authorizer-name ${AWS_AUTHORIZER_NAME} \
      --authorizer-function-arn arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${AWS_FUNCTION_NAME} \
      --token-key-name ${AWS_TOKEN_HEADER_NAME} \
      --token-signing-public-keys FIRST_KEY="${device_public_key}" \
      --status ACTIVE
else
  echo "Creating authorizer..."
  aws iot create-authorizer \
      --authorizer-name ${AWS_AUTHORIZER_NAME} \
      --authorizer-function-arn arn:aws:lambda:${AWS_REGION}:${AWS_ACCOUNT_ID}:function:${AWS_FUNCTION_NAME} \
      --token-key-name ${AWS_TOKEN_HEADER_NAME} \
      --token-signing-public-keys FIRST_KEY="${device_public_key}" \
      --status ACTIVE
fi
