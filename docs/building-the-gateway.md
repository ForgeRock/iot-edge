# Building the IoT Gateway

ForgeRock does not deliver binaries for the IoT Gateway as there are simply too many operating system and
architecture combinations to support. One of the reasons we chose the Go programming language is for its easy to use
build tooling and great support for cross-compilation to target systems.  

## Building on the target system

Build the Gateway into a binary:

```bash
cd cmd/gateway/
go build -o ./bin/gateway .
```

Use the help flag to see the available command line options for the Gateway:

```bash
./bin/gateway -h
```

## Cross-compile for the target system

The target system can be specified with a combination of the `$GOOS` and `$GOARCH` environment variables.

To run the gateway on an arm 32-bit processor (for example, a Raspberry Pi 3 running in 32-bit mode), build for
`linux/arm`:

```bash
GOOS=linux GOARCH=arm go build -o ./bin/gateway .
```

See the [complete list](https://golang.org/doc/install/source#environment) of possible cross-compilation targets.

See the Go command [environment variables](https://golang.org/cmd/go/#hdr-Environment_variables) for more build options.
