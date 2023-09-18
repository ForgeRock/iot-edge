#
# The contents of this file are subject to the terms of the Common Development and
# Distribution License (the License). You may not use this file except in compliance with the
# License.
#
# You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
# specific language governing permission and limitations under the License.
#
# When distributing Covered Software, include this CDDL Header Notice in each file and include
# the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
# Header, with the fields enclosed by brackets [] replaced by your own identifying
# information: "Portions Copyright [year] [name of copyright owner]".
#
# Copyright 2019-2023 ForgeRock AS.
#
FROM gcr.io/forgerock-io/am-base:7.3.0
USER root

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_OPTS="--no-install-recommends --yes"
RUN apt-get update \
        && apt-get install -y git \
        && apt-get clean \
        && rm -r /var/lib/apt/lists /var/cache/apt/archives

USER forgerock

# IAM-434: Preserves the native XUI code in a new location specifically for OAuth 2-related UI needs.
RUN cp -R /usr/local/tomcat/webapps/am/XUI /usr/local/tomcat/webapps/am/OAuth2_XUI
ENV CATALINA_USER_OPTS -Dorg.forgerock.am.oauth2.consent.xui_path=/OAuth2_XUI

COPY --chown=forgerock:root tmp/config /home/forgerock/cdk/config

# Use a custom logback. Comment out if you want to use the default json logger.
COPY --chown=forgerock:root logback.xml /usr/local/tomcat/webapps/am/WEB-INF/classes

# Until we move the base config to the new "base config layer" we need to remove from the am-cdk image.
RUN rm -rf $AM_HOME/config/services && \
    mkdir $AM_HOME/config/services

ENV FBC_BASE_PATHS="-Dcom.forgerock.am.fileconfig.basepaths=/home/forgerock/base/config/services,/home/forgerock/cdk/config/services"
