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

# set GO environment variables
export GOPATH=$(pwd)/vendor
export GO111MODULE=on

# uncomment to switch on DTLS debug
#export PION_LOG_TRACE=all

case "$1" in
anvil)
  # Run the IoT SDK tests
  go run github.com/ForgeRock/iot-edge/tests/iotsdk
	;;
test)
  # Run the IoT unit tests
  go test -v -p 1 -timeout 5s -coverprofile=coverage.out -failfast github.com/ForgeRock/iot-edge/...
	;;
example)
  # Run the example program
  go run github.com/ForgeRock/iot-edge/examples/"$2" "${@:3}"
	;;
coverage)
  go tool cover -html=coverage.out
  ;;
doc)
  # Download latest godoc to get module support, godoc is no longer packaged with go.
  go get -u golang.org/x/tools/cmd/godoc
  echo
  echo "Go to: http://localhost:6060/pkg/github.com/ForgeRock/iot-edge/"
  "$GOPATH"/bin/godoc
  ;;
*)
  echo "unknown script option: $1"
  exit 1
  ;;
esac

echo '
 ______     __  __
/\  __ \   /\ \/ /
\ \ \/\ \  \ \  _"-.
 \ \_____\  \ \_\ \_\
  \/_____/   \/_/\/_/
'
