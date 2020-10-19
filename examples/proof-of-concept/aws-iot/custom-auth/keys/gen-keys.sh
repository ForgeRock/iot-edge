#!/usr/bin/env bash

#
# Copyright 2019 ForgeRock AS
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

# Generate keys to use for authorizer token signature and JWT Bearer signature
if [ ! -f device-private.pem ]; then
    openssl genrsa -out device-private.pem 2048
fi
if [ ! -f device-public.pem ]; then
    openssl rsa -in device-private.pem -outform PEM -pubout -out device-public.pem
fi
if [ ! -f device-public.crt ]; then
    openssl req -new -x509 -key device-private.pem -out device-public.crt -days 1825
fi