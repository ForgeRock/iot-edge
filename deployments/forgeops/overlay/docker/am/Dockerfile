FROM gcr.io/forgerock-io/am-cdk/pull-requests:7.4.0-PR-18491-4-bfc4ced970beccc083ed4ec9ed5f896ccd1242d6

ARG CONFIG_PROFILE=cdk
RUN echo "\033[0;36m*** Building '${CONFIG_PROFILE}' profile ***\033[0m"
COPY  --chown=forgerock:root config-profiles/${CONFIG_PROFILE}/ /home/forgerock/openam/

COPY --chown=forgerock:root *.sh /home/forgerock/

WORKDIR /home/forgerock

# If you want to debug AM uncomment these lines:
ENV JPDA_TRANSPORT=dt_socket
ENV JPDA_ADDRESS *:9009
