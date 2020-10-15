FROM golang:1.14-buster

RUN apt-get update --yes && \
    apt-get install --yes \
    curl \
    vim \
    build-essential \
    libjson-c-dev \
    libssl-dev \
    uuid-dev && \
    apt-get clean --yes

# download and install mosquitto
RUN curl http://mosquitto.org/files/source/mosquitto-1.5.8.tar.gz | tar zxf - && \
    cd mosquitto-1.5.8 && make && make install && cd - && rm -rf mosquitto-1.5.8

# Install the cert
ADD tmp/_wildcard.iam.example.com.pem /usr/local/share/ca-certificates/_wildcard.iam.example.com.crt
RUN update-ca-certificates

WORKDIR /mosquitto

# create directories and copy across config and plugin
RUN mkdir -p config plugin log

# build OAuth2 auth plugin
ADD oauth2-auth-plugin plugin
ENV CGO_CFLAGS="-I/usr/local/include"
ENV CGO_ENABLED=1
RUN cd ./plugin && go build -o oauth2-auth-plugin.so -buildmode=c-shared .

# copy across configuration
COPY config/mosquitto.conf config/

# add a "admin" user to the mosquitto password file
RUN touch config/passwd && mosquitto_passwd -b config/passwd admin password

# add user for mosquitto
RUN useradd mosquitto && chown -R mosquitto: /mosquitto

# add the mosquitto library to the path for mosquitto_pub/sub
ENV LD_LIBRARY_PATH="/usr/local/lib:${LD_LIBRARY_PATH}"

CMD ["mosquitto", "-c", "/mosquitto/config/mosquitto.conf"]
