FROM golang:1.19-buster

WORKDIR /root/thing

# Get dependencies
COPY mosquitto-demo .
RUN go mod download
