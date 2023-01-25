module github.com/ForgeRock/iot-edge/v7/cmd/gateway

go 1.19

require (
	github.com/ForgeRock/iot-edge/v7 v7.2.0
	github.com/jessevdk/go-flags v1.4.0
)

require (
	github.com/go-ocf/go-coap v0.0.0-20200325133359-298a26e4e9c8 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pion/dtls/v2 v2.1.5 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport v0.14.1 // indirect
	github.com/pion/udp v0.1.2 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/square/go-jose.v2 v2.4.1 // indirect
)

replace github.com/ForgeRock/iot-edge/v7 => ../../
