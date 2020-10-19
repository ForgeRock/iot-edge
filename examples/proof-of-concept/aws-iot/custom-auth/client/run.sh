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

source ../../.env

AM_URL=https://$FR_FQDN/am
AM_INTROSPECT_URL=$AM_URL/oauth2/introspect

go mod download
go run client -am-base-url "${AM_URL}" -am-introspect-url "${AM_INTROSPECT_URL}" -aws-iot-endpoint "${AWS_IOT_ENDPOINT}"
