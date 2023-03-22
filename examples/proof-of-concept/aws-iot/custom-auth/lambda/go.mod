module lamda

go 1.19

replace github.com/ForgeRock/iot-edge/examples => ../../../../../examples

require (
	github.com/ForgeRock/iot-edge/examples v0.0.0-20230222181101-3767b5a71605
	github.com/ForgeRock/iot-edge/v7 v7.2.0
	github.com/aws/aws-lambda-go v1.19.1
)

require (
	github.com/go-ocf/go-coap v0.0.0-20200325133359-298a26e4e9c8 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/pion/dtls/v2 v2.2.4 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.0.0 // indirect
	github.com/pion/udp v0.1.4 // indirect
	golang.org/x/crypto v0.5.0 // indirect
	golang.org/x/net v0.5.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
)
