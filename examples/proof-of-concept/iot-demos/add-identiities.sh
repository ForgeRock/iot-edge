#!/usr/bin/env bash
set -e

#
# Copyright 2021 ForgeRock AS
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

LDIF_FILE=identities.ldif

if [ $# -eq 0 ]; then
    echo "No DS password provided"
    exit 1
fi
DS_PASSWORD=$1

echo "====================================================="
echo "Adding identities and groups to the platform"
echo "====================================================="
kubectl cp "./$LDIF_FILE" ds-idrepo-0:/opt/opendj/ldif/
kubectl exec ds-idrepo-0 -- ./bin/ldapmodify --no-prompt -w "$DS_PASSWORD"  "./ldif/$LDIF_FILE"
