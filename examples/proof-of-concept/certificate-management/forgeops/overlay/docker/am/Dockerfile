FROM --platform=linux/amd64 gcr.io/forgerock-io/am-cdk:7.4.0

USER root

RUN apt-get update \
        && apt-get install -y git wget \
        && apt-get clean \
        && rm -r /var/lib/apt/lists /var/cache/apt/archives

# Fetch the CA cert for the cert test service and convert it to DER.
# Import the DER encoded public certificate into the Java certificate store. This allows us to use TLS when
# calling into AM from Java processes like the Groovy scripting engine.
RUN wget http://testrfc7030.com/dstcax3.pem && \
    openssl x509 -outform der -in dstcax3.pem -out dstcax3.crt && \
    keytool -importcert \
            -trustcacerts \
            -noprompt \
            -alias testrfc7030.com \
            -file dstcax3.crt \
            -storepass changeit \
            -keystore ${JAVA_HOME}/lib/security/cacerts

USER forgerock

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY  --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /home/forgerock/openam/

COPY --chown=forgerock:root *.sh /home/forgerock/
COPY --chown=forgerock:root est-node-1.0.0-SNAPSHOT.jar /usr/local/tomcat/webapps/am/WEB-INF/lib

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
ENV JPDA_TRANSPORT=dt_socket
ENV JPDA_ADDRESS *:9009
