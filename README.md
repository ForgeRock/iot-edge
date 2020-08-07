[![GoDoc](https://godoc.org/github.com/ForgeRock/iot-edge/pkg?status.svg)](https://godoc.org/github.com/ForgeRock/iot-edge/pkg)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ForgeRock/iot-edge/blob/main/LICENSE)
[![Lint](https://github.com/ForgeRock/iot-edge/workflows/golangci-lint/badge.svg)](https://github.com/ForgeRock/iot-edge/actions?query=workflow%3Agolangci-lint)
[![go test](https://github.com/ForgeRock/iot-edge/workflows/go-test/badge.svg)](https://github.com/ForgeRock/iot-edge/actions?query=workflow%3Ago-test)

# ForgeRock IoT Edge

ForgeRock IoT Edge is an open source project containing the IoT edge tier components of the ForgeRock Identity Platform.

<img src="docs/iot-edge-components.svg" width="450"/>

## Thing SDK

The _Thing SDK_ enables a _thing_, which can be either a physical _device_ or a software _service_, to register and
authenticate without human interaction. Once registered, the _thing_ will be represented by a digital identity in the
ForgeRock Identity Platform and can authenticate itself in order to interact with the platform tier.

See the [getting started guide](docs/getting-started.md) for information about how to use the SDK.

## Thing Gateway
The _Thing Gateway_ is an application that enables more constrained devices to interact with the ForgeRock Identity
Platform by acting as a proxy between a _thing_ and the Platform.

See the [build the Gateway guide](docs/building-the-gateway.md) for information about building the Gateway.
