# Note: M5 integration with AM currently not working
FROM --platform=linux/amd64 gcr.io/forgerock-io/idm-cdk:7.4.0

COPY debian-buster-sources.list /etc/apt/sources.list

# Harden IDM by removing the Felix OSGI Console. Unless you are a ForgeRock developer, the
# console is rarely required. Your configuration should NOT include conf/felix.webconsole.json
RUN rm -f bundle/org.apache.felix.webconsole*.jar  && \
    rm -f bundle/openidm-felix-webconsole-*.jar

# Remove this once https://bugster.forgerock.org/jira/browse/OPENIDM-16100 is integrated
# This sets the RAM based on cgroups to 65% of the container memory
ENV JAVA_OPTS -XX:MaxRAMPercentage=65 -XX:InitialRAMPercentage=65 -XX:MaxTenuringThreshold=1 -Djava.security.egd=file:/dev/urandom -XshowSettings:vm  -XX:+PrintFlagsFinal
ENV JAVA_TOOL_OPTIONS "-agentlib:jdwp=transport=dt_socket,address=8088,server=y,suspend=n"

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /opt/openidm
COPY --chown=forgerock:root tmp/config-profiles/${CONFIG_PROFILE}/ /opt/openidm
COPY --chown=forgerock:root bin/import-pem-certs.sh /opt/openidm/bin
COPY --chown=forgerock:root . /opt/openidm

ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/microsoft/azure/sdk/iot/iot-service-client/1.26.0/iot-service-client-1.26.0.jar /opt/openidm/lib/iot-service-client-1.26.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/microsoft/azure/sdk/iot/iot-deps/0.11.0/iot-deps-0.11.0.jar /opt/openidm/lib/iot-deps-0.11.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/code/gson/gson/2.5/gson-2.5.jar /opt/openidm/lib/gson-2.5.jar
