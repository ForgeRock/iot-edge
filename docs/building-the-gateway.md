# Building the Gateway

## Prerequisites

- [Docker](https://docs.docker.com/engine/install/)
- [Go](https://golang.org/doc/install)

## Get the Gateway code

Clone this repository

```bash
git clone git@github.com:ForgeRock/iot-edge.git
```

and change directory to the repository root:

```bash
cd iot-edge
```

## Building on the target system

Build the Gateway into a binary:

```bash
go build -o ./bin/gateway ./cmd/gateway
```

Use the help flag to see the available command line options for the Gateway:

```bash
./bin/gateway -h
```

## Building in Docker

Alternatively, a Golang docker container can be used to build the Gateway. Get the `golang` docker image:

```bash
docker pull golang:1.13
```

To build for `linux/amd64`:

```bash
docker run --rm -it \
    -v "$PWD":/go/src/iot-edge -w /go/src/iot-edge \
    golang:1.13 \
    go build -o ./bin/gateway ./cmd/gateway
```

To run the Gateway on an arm 32-bit processor (for example, a Raspberry Pi 3 running in 32-bit mode), build for
`linux/arm`:

```bash
docker run --rm -it \
    -v "$PWD":/go/src/iot-edge -w /go/src/iot-edge \
    -e GOOS=linux -e GOARCH=arm \
    golang:1.13 \
    go build -o ./bin/gateway ./cmd/gateway
```
