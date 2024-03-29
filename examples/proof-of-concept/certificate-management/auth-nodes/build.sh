#!/usr/bin/env bash

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

if [ -n "$1" ]; then
  PLUGIN_DIR=$1
  echo "Plugin directory: $PLUGIN_DIR"
fi

if [ -z "$PLUGIN_DIR" ]; then
  echo "Plugin directory must not be empty"
exit 1
fi

mvn clean install
rm -rf "$PLUGIN_DIR" && mkdir -p "$PLUGIN_DIR"
cp target/est-node-1.0.0-SNAPSHOT.jar "$PLUGIN_DIR"
