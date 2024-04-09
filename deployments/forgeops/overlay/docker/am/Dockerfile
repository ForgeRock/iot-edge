FROM --platform=linux/amd64 gcr.io/forgerock-io/am-cdk/pull-requests:7.6.0-PR-20979-3-e4eb3ed46402b791f398c4f4a0c2d7840041dd1d

ARG CONFIG_PROFILE=cdk
# RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY  --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /home/forgerock/openam/

COPY --chown=forgerock:root *.sh /home/forgerock/

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
ENV JPDA_TRANSPORT=dt_socket
ENV JPDA_ADDRESS *:9009
