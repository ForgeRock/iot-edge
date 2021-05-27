# Note: M5 integration with AM currently not working
FROM gcr.io/forgerock-io/idm:7.1.0

# Harden IDM by removing the Felix OSGI Console. Unless you are a ForgeRock developer, the
# console is rarely required. Your configuration should NOT include conf/felix.webconsole.json
RUN rm -f bundle/org.apache.felix.webconsole*.jar  && \
    rm -f bundle/openidm-felix-webconsole-*.jar

# Removes unwanted default config bundled out of the box.
RUN rm conf/felix.webconsole.json
RUN rm conf/selfservice.propertymap.json

# Remove this once https://bugster.forgerock.org/jira/browse/OPENIDM-16100 is integrated
# This sets the RAM based on cgroups to 65% of the container memory
ENV JAVA_OPTS -XX:MaxRAMPercentage=65 -XX:InitialRAMPercentage=65 -XX:MaxTenuringThreshold=1 -Djava.security.egd=file:/dev/urandom -XshowSettings:vm  -XX:+PrintFlagsFinal

COPY --chown=forgerock:root . /opt/openidm

ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/code/gson/gson/2.5/gson-2.5.jar /opt/openidm/lib/gson-2.5.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/apis/google-api-services-cloudiot/v1-rev20200901-1.30.10/google-api-services-cloudiot-v1-rev20200901-1.30.10.jar /opt/openidm/lib/google-api-services-cloudiot-v1-rev20200901-1.30.10.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/auth/google-auth-library-oauth2-http/0.22.0/google-auth-library-oauth2-http-0.22.0.jar /opt/openidm/lib/google-auth-library-oauth2-http-0.22.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/auth/google-auth-library-credentials/0.22.0/google-auth-library-credentials-0.22.0.jar /opt/openidm/lib/google-auth-library-credentials-0.22.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/http-client/google-http-client/1.37.0/google-http-client-1.37.0.jar /opt/openidm/lib/google-http-client-1.37.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/http-client/google-http-client-jackson2/1.37.0/google-http-client-jackson2-1.37.0.jar /opt/openidm/lib/google-http-client-jackson2-1.37.0.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=io/opencensus/opencensus-api/0.27.1/opencensus-api-0.27.1.jar /opt/openidm/lib/opencensus-api-0.27.1.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=io/opencensus/opencensus-contrib-http-util/0.27.1/opencensus-contrib-http-util-0.27.1.jar /opt/openidm/lib/opencensus-contrib-http-util-0.27.1.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=io/grpc/grpc-stub/1.32.2/grpc-stub-1.32.2.jar /opt/openidm/lib/grpc-stub-1.32.2.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=io/grpc/grpc-context/1.32.2/grpc-context-1.32.2.jar /opt/openidm/lib/grpc-context-1.32.2.jar
ADD --chown=forgerock:root https://search.maven.org/remotecontent?filepath=com/google/api-client/google-api-client/1.30.11/google-api-client-1.30.11.jar /opt/openidm/lib/google-api-client-1.30.11.jar
