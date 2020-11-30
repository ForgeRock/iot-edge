#!/usr/bin/env bash
set -e

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

if [ -f .env ]; then
  source .env
else
  echo '##########################################################'
  echo '# This script requires the following variables to be declared in a file called ".env".'
  echo '# These variables must reflect your own environment.'
  echo '##########################################################'
  echo '# The account and region of your AWS environment.'
  echo 'AWS_ACCOUNT_ID=1234567890'
  echo 'AWS_REGION=us-west-2'
  echo ''
  echo '# The AWS IoT endpoint used to publish messages. Retrieve with the command `aws iot describe-endpoint`.'
  echo 'AWS_IOT_ENDPOINT=b35h885e3pfog.iot.us-west-2.amazonaws.com'
  echo ''
  echo '# Variables for deploying to GKE shared cluster, see'
  echo '# https://backstage.forgerock.com/docs/forgeops/7/devops-cloud-implementation-env.html'
  echo 'DOCKER_REGISTRY=my-docker-registry'
  echo 'KUBE_CTX=my-kubernetes-context'
  echo 'KUBE_NS=my-kubernetes-namespace'
  echo ''
  echo '# The fully qualified domain name of the ForgeRock platform'
  echo 'FR_FQDN=$KUBE_NS.iam.example.com'
  echo ''
  exit 1
fi


POC_DIR=$(PWD)
FORGEOPS_DIR=$POC_DIR/../../../deployments/forgeops/tmp
BASE_OVERLAY_DIR=$POC_DIR/../../../deployments/forgeops/overlay
POC_OVERLAY_DIR=$POC_DIR/forgeops
FR_PLATFORM_PASSWORD=$(openssl rand -base64 32 | tr =/ 0 | tr l+ 1)

echo "====================================================="
echo "Deploy the connector"
echo "====================================================="
cd $POC_DIR/registry-connector
./deploy.sh
cd $POC_DIR

echo "====================================================="
echo "Deploy and configure AWS custom authorizer function"
echo "====================================================="
cd $POC_DIR/custom-auth/lambda
./deploy.sh
cd $POC_DIR

echo "====================================================="
echo "Clone ForgeOps"
echo "====================================================="
rm -rf "$FORGEOPS_DIR" && mkdir -p "$FORGEOPS_DIR" && cd "$FORGEOPS_DIR"
git clone https://github.com/ForgeRock/forgeops.git .
git checkout tags/2020.08.07-ZucchiniRicotta.1

echo "====================================================="
echo "Create $KUBE_NS namespace"
echo "====================================================="
set +e
kubectl create namespace $KUBE_NS
kubens $KUBE_NS
set -e

echo "====================================================="
echo "Configure Skaffold to use default repo"
echo "====================================================="
skaffold config set default-repo $DOCKER_REGISTRY -k $KUBE_CTX

echo "====================================================="
echo "Overlay base and custom files"
echo "====================================================="
cp -rf "$BASE_OVERLAY_DIR"/* "$FORGEOPS_DIR"
cp -rf "$POC_OVERLAY_DIR"/* "$FORGEOPS_DIR"
sed -i '' "s/&{kube.ns}/$KUBE_NS/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"
sed -i '' "s/&{fr.fqdn}/$FR_FQDN/g" "$FORGEOPS_DIR/kustomize/overlay/7.0/all/kustomization.yaml"

echo "====================================================="
echo "Substitute platform password"
echo "====================================================="
sed -i '' "s/&{platform.password}/$FR_PLATFORM_PASSWORD/g" "$FORGEOPS_DIR/config/7.0/iot/am/config/services/realm/root/sunidentityrepositoryservice/1.0/organizationconfig/default/opendj.json"

echo "====================================================="
echo "Initialise 'iot' configuration"
echo "====================================================="
"$FORGEOPS_DIR"/bin/config.sh init --profile iot --version 7.0
"$FORGEOPS_DIR"/bin/config.sh init --profile iot --component ds --version 7.0

echo "====================================================="
echo "Configure global password"
echo "====================================================="
password_file="$FORGEOPS_DIR/docker/forgeops-secrets/forgeops-secrets-image/config/OVERRIDE_ALL_PASSWORDS.txt"
touch "$password_file"
echo "$FR_PLATFORM_PASSWORD" > "$password_file"

echo "====================================================="
echo "Clean out existing pods"
echo "====================================================="
skaffold delete
"$FORGEOPS_DIR"/bin/clean.sh

echo "====================================================="
echo "Run the platform"
echo "====================================================="
skaffold run

echo "====================================================="
echo "~~~ Platform login details ~~~"
echo "URL: https://$FR_FQDN/platform"
echo "Username: amadmin"
echo "Password: $FR_PLATFORM_PASSWORD"
echo ""
echo "~~~ AWS Access Key Details ~~~"
cat $POC_DIR/registry-connector/iot-access-key.secret
echo "====================================================="
