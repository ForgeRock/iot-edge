#
# Copyright 2023 ForgeRock AS
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

source ./.env

mkdir am/cache
if [[ ! -f am/cache/AM-${AM_VERSION}.war ]]; then
  mkdir -p am/cache/
  wget https://storage.googleapis.com/forgerock-build-assets-live/pkg/servers/forgerock/OpenAM/staging/${AM_VERSION}/AM-${AM_VERSION}.war -O am/cache/AM-${AM_VERSION}.war
fi

if [[ ! -f am/cache/Amster-${AM_VERSION}.zip ]]; then
  mkdir -p am/cache/
  wget https://storage.googleapis.com/forgerock-build-assets-live/pkg/servers/forgerock/OpenAM/staging/${AM_VERSION}/Amster-${AM_VERSION}.zip -O am/cache/Amster-${AM_VERSION}.zip
fi

docker build am --progress plain --no-cache -t am-embedded:latest \
  --build-arg AM_URL=${AM_URL} \
  --build-arg AM_HOME=${AM_HOME} \
  --build-arg AM_CONFIG=${AM_CONFIG} \
  --build-arg AM_PASSWORD=${AM_PASSWORD} \
  --build-arg AM_VERSION=${AM_VERSION} \
  --build-arg AMSTER_HOME=${AMSTER_HOME} \
  --build-arg IMPORT_CONFIG=${IMPORT_CONFIG}

docker run -d --env-file .env -p 8080:8080 --name am-embedded am-embedded:latest
