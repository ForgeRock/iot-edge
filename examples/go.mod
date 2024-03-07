module github.com/ForgeRock/iot-edge/examples

go 1.21

require (
	github.com/ForgeRock/iot-edge/v7 v7.4.0
	github.com/go-jose/go-jose/v3 v3.0.3
	github.com/google/uuid v1.4.0
)

require (
	github.com/go-ocf/go-coap v0.0.0-20200325133359-298a26e4e9c8 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

replace github.com/ForgeRock/iot-edge/v7 => ../
