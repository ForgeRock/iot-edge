module github.com/ForgeRock/iot-edge/v7/cmd/gateway

go 1.21

require (
	github.com/ForgeRock/iot-edge/v7 v7.4.0
	github.com/jessevdk/go-flags v1.5.0
)

require (
	github.com/go-jose/go-jose/v3 v3.0.1 // indirect
	github.com/go-ocf/go-coap v0.0.0-20200325133359-298a26e4e9c8 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/ForgeRock/iot-edge/v7 => ../../
