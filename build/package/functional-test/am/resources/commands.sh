#!/bin/bash

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


#
# Start tomcat and wait until startup is complete
#
function start_tomcat() {
    # Clean the logs so we don't read the previous startup message
	rm -f ${CATALINA_HOME}/logs/catalina.out

    # Start tomcat
    ${CATALINA_HOME}/bin/catalina.sh start

    # Wait for tomcat to complete startup
    count=60
    printf "\nWaiting for server startup"
    while [[ -z "$(cat ${CATALINA_HOME}/logs/catalina.out | grep "Server startup")" && count -gt 0 ]]; do
        sleep 2 && printf "."
        ((count--))
    done

    # If tomcat does not start in 1 minute then kill the process and cat the log
    if [[ count -eq 0 ]]; then
        printf "\nServer failed to startup normally. Tomcat log:\n\n"
        cat ${CATALINA_HOME}/logs/catalina.out
        pkill -9 -f tomcat
    else
        printf "\nServer started\n"
    fi
}

#
# Stop tomcat and wait until shutdown is complete
#
function stop_tomcat() {
    # Stop tomcat
    ${CATALINA_HOME}/bin/catalina.sh stop

    # Wait for tomcat to complete shutdown
    count=30
    printf "\nWaiting for server shutdown"
    while [[ -z "$(cat ${CATALINA_HOME}/logs/catalina.out | grep "Destroying ProtocolHandler")" && count -gt 0 ]]; do
        sleep 2 && printf "."
        ((count--))
    done

    # If tomcat does not stop in 1 minute then kill the process and cat the log
    if [[ count == 0 ]]; then
        echo "Server failed to shutdown normally. Tomcat log:\n\n"
        cat ${CATALINA_HOME}/logs/catalina.out
        pkill -9 -f tomcat
    else
        printf "\nServer stopped\n"
    fi
}

#
# Restart tomcat
#
function restart_tomcat() {
    stop_tomcat
    sleep 5
    start_tomcat
}

#
# Start tomcat in docker container and install AM with Amster
#
function install_am() {
    start_tomcat
    echo "Installing OpenAM"
    cd ${AMSTER_HOME}
    ./amster install-am.amster -D AM_URL=${AM_URL} -D AM_PASSWORD=${AM_PASSWORD} -D AM_HOME=${AM_HOME}
    # Execute and notify the caller if this fails.
    if [[ $? -ne 0 ]]; then
        echo "Amster Installation failed"
        exit 2
    fi
    cd - &>/dev/null
    if [[ $IMPORT_CONFIG == true ]]; then
        import_config
    fi
}


#
# Import AM configuration.
#
function import_config() {
    echo "Import AM configuration from: $AM_CONFIG"
    cd ${AMSTER_HOME}
    ./amster import-config.amster \
        -D AM_URL=${AM_URL} \
        -D AMSTER_KEY=${AM_HOME}/security/keys/amster/amster_rsa \
        -D AM_CONFIG_PATH=${AM_CONFIG}
    cd - &>/dev/null
}

#
# Export AM configuration. Expects AM to be running in docker container and export path as parameter.
#
function export_config() {
    echo "Exporting AM configuration to: $1"
    cd ${AMSTER_HOME}
    ./amster export-config.amster \
        -D AM_URL=${AM_URL} \
        -D AMSTER_KEY=${AM_HOME}/security/keys/amster/amster_rsa \
        -D AM_CONFIG_PATH=${1}
    cd - &>/dev/null
}
