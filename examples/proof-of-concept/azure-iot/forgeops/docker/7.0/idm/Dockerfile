# Note: M5 integration with AM currently not working
FROM gcr.io/forgerock-io/idm:7.0.0

# Harden IDM by removing the Felix OSGI Console. Unless you are a ForgeRock developer, the
# console is rarely required. Your configuration should NOT include conf/felix.webconsole.json
RUN rm bundle/org.apache.felix.webconsole*.jar  && \
    rm bundle/openidm-felix-webconsole-*.jar

# Removes any existing conf files that might conflict with our config. This includes the embedded ds repo.
RUN rm -fr /opt/openidm/conf
ENV JAVA_OPTS "-server -XX:MaxRAMPercentage=75"
ENV JAVA_TOOL_OPTIONS "-agentlib:jdwp=transport=dt_socket,address=8088,server=y,suspend=n"
COPY --chown=forgerock:root . /opt/openidm

ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/microsoft/azure/sdk/iot/iot-service-client/1.26.0/iot-service-client-1.26.0.jar /opt/openidm/lib/iot-service-client-1.26.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/microsoft/azure/sdk/iot/iot-deps/0.11.0/iot-deps-0.11.0.jar /opt/openidm/lib/iot-deps-0.11.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/code/gson/gson/2.5/gson-2.5.jar /opt/openidm/lib/gson-2.5.jar
