FROM gcr.io/forgerock-io/am-base:7.2.0
USER root

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_OPTS="--no-install-recommends --yes"
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

# IAM-434: Preserves the native XUI code in a new location specifically for OAuth 2-related UI needs.
RUN cp -R /usr/local/tomcat/webapps/am/XUI /usr/local/tomcat/webapps/am/OAuth2_XUI
ENV CATALINA_USER_OPTS -Dorg.forgerock.am.oauth2.consent.xui_path=/OAuth2_XUI

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY  --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /home/forgerock/openam/

# Use a custom logback. Comment out if you want to use the default json logger.
COPY --chown=forgerock:root logback.xml /usr/local/tomcat/webapps/am/WEB-INF/classes

COPY --chown=forgerock:root est-node-1.0.0-SNAPSHOT.jar /usr/local/tomcat/webapps/am/WEB-INF/lib

COPY --chown=forgerock:root *.sh /home/forgerock/

WORKDIR /home/forgerock/openam

# This lets the user see what FBC files have been modified
RUN git config --global user.email "cloud-deployment@forgerock.com" && \
    git config --global user.name "Cloud Deployment" && \
    git add . && \
    git commit -m "CDM file-based configuration overlay"

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
ENV JPDA_TRANSPORT=dt_socket
ENV JPDA_ADDRESS *:9009