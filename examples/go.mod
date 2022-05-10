module github.com/ForgeRock/iot-edge/examples

go 1.15

require (
	github.com/ForgeRock/iot-edge/v7 v7.1.0
	github.com/google/uuid v1.3.0
	gopkg.in/square/go-jose.v2 v2.4.1
)

replace github.com/ForgeRock/iot-edge/v7 => ../
