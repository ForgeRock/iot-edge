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

Alternatively, the Golang docker container can be used to build the Gateway for `linux/amd64`:

```bash
docker pull golang:1.13
docker run --rm -it -v "$PWD":/go/src/iot-edge -w /go/src/iot-edge golang:1.13 go build -o ./bin/gateway ./cmd/gateway
```
