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

FROM tomcat:9-jdk11

ARG AM_URL
ARG AM_HOME
ARG AM_PASSWORD
ARG AM_CONFIG
ARG AM_VERSION
ARG AMSTER_HOME
ARG AMSTER_KEY
ARG IMPORT_CONFIG

RUN apt-get update --yes && \
    apt-get install --yes \
    unzip && \
    apt-get clean --yes

# Add AM and Amster
ADD cache/AM-"$AM_VERSION".war "$CATALINA_HOME"/webapps/am.war
ADD cache/Amster-"$AM_VERSION".zip /tmp/amster.zip
RUN mkdir -p /opt/forgerock && unzip -q /tmp/amster.zip -d /opt/forgerock && rm /tmp/amster.zip

# Add installation scripts
ADD resources/install-am.amster /opt/forgerock/amster/install-am.amster
ADD resources/export-config.amster /opt/forgerock/amster/export-config.amster
ADD resources/import-config.amster /opt/forgerock/amster/import-config.amster
ADD resources/commands.sh /opt/forgerock/commands.sh

# Install AM and import configuration
RUN export AM_URL=${AM_URL} && \
    export AM_HOME=${AM_HOME} && \
    export AM_CONFIG=${AM_CONFIG} && \
    export AM_PASSWORD=${AM_PASSWORD} && \
    export AMSTER_HOME=${AMSTER_HOME} && \
    export IMPORT_CONFIG=${IMPORT_CONFIG} && \
    /bin/bash -c "source /opt/forgerock/commands.sh && install_am"

CMD ["/usr/local/tomcat/bin/catalina.sh", "jpda", "run"]
