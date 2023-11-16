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

FROM golang:1.21-bullseye

WORKDIR /root/things

# Copy demo code
COPY cmd cmd
COPY go.mod .
COPY go.sum .

# Build the executable
RUN cd /root/things/cmd/mqtt-client && go install

WORKDIR /go/bin
COPY .secrets .

CMD ["mqtt-client"]
