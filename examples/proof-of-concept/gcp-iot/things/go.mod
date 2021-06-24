module github.com/ForgeRock/iot-edge/examples/proof-of-concept/gcp-iot/things

go 1.15

require (
	github.com/ForgeRock/iot-edge/examples v0.0.0-20210616115124-5011e360d90b
	github.com/ForgeRock/iot-edge/v7 v7.1.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/jessevdk/go-flags v1.4.0
	github.com/jpillora/backoff v1.0.0
	golang.org/x/net v0.0.0-20200425230154-ff2c4b7c35a0 // indirect
)

replace github.com/ForgeRock/iot-edge/examples => ../../../

replace github.com/ForgeRock/iot-edge/v7 => ../../../../
