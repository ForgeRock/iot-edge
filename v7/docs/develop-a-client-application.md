# Develop a client application with the Thing SDK

This example will show you how to create a client application for a thing called _Gopher_. The thing will be
manually registered in AM and authenticated with a username/password authentication flow.

Prepare a directory for your Go project:
```bash
mkdir -p things/cmd/gopher
cd things
touch cmd/gopher/main.go
```

Open _cmd/gopher/main.go_ in a text editor and add the following code to it:
```go
package main

import (
	"github.com/ForgeRock/iot-edge/pkg/builder"
	"github.com/ForgeRock/iot-edge/pkg/callback"
	"log"
	"net/url"
)

func main() {
	amURL, err := url.Parse("http://am.localtest.me:8080/am")
	if err != nil {
		log.Fatal(err)
	}
	_, err = builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("Example").
		HandleCallbacksWith(
			callback.NameHandler{Name: "Gopher"},
			callback.PasswordHandler{Password: "5tr0ngG3n3r@ted"}).
		Create()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Gopher successfully authenticated.")
}
```

Create a new Go module:
```bash
go mod init example.com/things
```
This will create a _go.mod_ file that specifies your project dependencies and versions.  

Before we can run the application, we need to create the _Gopher_ identity in AM.
 
Get an admin SSO token:
```bash
curl --request POST 'http://am.localtest.me:8080/am/json/authenticate' \
--header 'Content-Type: application/json' \
--header 'X-OpenAM-Username: amAdmin' \
--header 'X-OpenAM-Password: changeit' \
--header 'Accept-API-Version: resource=2.0, protocol=1.0'
```

Save the `tokenId` received from this request to a variable:
```bash
tokenId="5oXAB6....lMxAAA.*"
```

Create the `Gopher` identity:
```bash
curl -v --request PUT 'http://am.localtest.me:8080/am/json/realms/root/users/Gopher' \
--header 'Content-Type: application/json' \
--header 'Accept-Api-Version: resource=4.0, protocol=2.1' \
--cookie "iPlanetDirectoryPro=${tokenId}" \
--data '{
    "thingType": "device",
    "userPassword": "5tr0ngG3n3r@ted"
}'
```

Build an executable for your client application and run it to authenticate _Gopher_:
```bash
go build example.com/things/cmd/gopher
./gopher
```
