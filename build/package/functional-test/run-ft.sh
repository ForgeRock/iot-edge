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

printf "\nWaiting for AM to start up"
count=10
while [[ count -gt 0 ]]; do
  sleep 2 && printf "."
  ((count--))
  response=$(curl --write-out %{http_code} --silent --connect-timeout 5 --output /dev/null ${AM_URL}/json/serverinfo/* )
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

docker build iot-edge --progress plain -t iot-edge-ft:latest

cd ../../../
IOT_EDGE_DIR=$PWD
docker run --network host --name iot-edge-ft --volume "${IOT_EDGE_DIR}:/go/iot-edge" iot-edge-ft:latest

docker container rm -f iot-edge-ft
