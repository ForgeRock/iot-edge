module github.com/ForgeRock/iot-edge/examples

go 1.19

require (
	github.com/ForgeRock/iot-edge/v7 v7.2.0
	github.com/google/uuid v1.3.0
	gopkg.in/square/go-jose.v2 v2.4.1
)

require (
	github.com/go-ocf/go-coap v0.0.0-20200325133359-298a26e4e9c8 // indirect
	github.com/pion/dtls/v2 v2.0.0-rc.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	golang.org/x/crypto v0.0.0-20200128174031-69ecbb4d6d5d // indirect
	golang.org/x/net v0.0.0-20200320220750-118fecf932d8 // indirect
	golang.org/x/sys v0.0.0-20220913175220-63ea55921009 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
)

replace github.com/ForgeRock/iot-edge/v7 => ../
