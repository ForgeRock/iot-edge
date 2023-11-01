FROM golang:1.21-bullseye

WORKDIR /root/thing

# Get dependencies
COPY rabbit-demo .
RUN go mod download
