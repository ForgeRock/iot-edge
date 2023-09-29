module github.com/ForgeRock/iot-edge/examples/proof-of-concept/gcp-iot/things

go 1.15

require (
	github.com/ForgeRock/iot-edge/examples v0.0.0-20210616115124-5011e360d90b
	github.com/ForgeRock/iot-edge/v7 v7.2.0
	github.com/golang-jwt/jwt/v4 v4.2.0
	github.com/jessevdk/go-flags v1.5.0
	github.com/jpillora/backoff v1.0.0
	golang.org/x/net v0.7.0 // indirect
)

replace github.com/ForgeRock/iot-edge/examples => ../../../

replace github.com/ForgeRock/iot-edge/v7 => ../../../../
