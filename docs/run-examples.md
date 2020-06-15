# Run the SDK Examples

### Prerequisites
 - [Docker](https://docs.docker.com/engine/install/)
 - [Go](https://golang.org/doc/install)

### Run and Configure AM
This step applies to all the examples.

Get the latest AM image,
```bash
docker pull gcr.io/forgerock-io/am/docker-build:latest
```
and run it:
```bash
docker run --name am --rm -ti \
    -e AM_ADMIN_PWD=password \
    -e TOMCAT_INSECURE=ENABLED \
    -p 8080:8080 \
    gcr.io/forgerock-io/am/docker-build:latest
```

Once the AM installation has completed, log in to http://am.localtest.me:8080/am with `amadmin`:`password`.

Go to [Services](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/services):
 - Add the _IoT Service_
 - Select _Create OAuth 2.0 Client_ and _Create OAuth 2.0 JWT Issuer_
 - Save Changes
 - Add the _OAuth2 Provider_ service

Go to the [IoT OAuth 2.0 Client](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/applications-oauth2-clients/clients/edit/forgerock-iot-oauth2-client):
 - Add `publish` to _Scope(s)_
 - Save Changes
 
### Simple Example

The simple example will authenticate and request an access token for the thing. It requires the thing to have a
preregistered identity.  

Create an [authentication tree](http://am.localtest.me:8080/am/ui-admin/#realms/%2F/authentication-trees) called `auth-tree`:

<img src="auth-tree.png" width="400"/>

Register the thing with AM's REST endpoints. Get an admin SSO token:
```bash
curl --request POST 'http://am.localtest.me:8080/am/json/authenticate' \
--header 'Content-Type: application/json' \
--header 'X-OpenAM-Username: amadmin' \
--header 'X-OpenAM-Password: password' \
--header 'Accept-API-Version: resource=2.0, protocol=1.0'
```
Replace `{tokenId}` in the following request with the `tokenId` received from the previous request and create the
thing identity:
```bash
curl -v --request PUT 'http://am.localtest.me:8080/am/json/realms/root/users/simple-thing' \
--header 'Content-Type: application/json' \
--header 'Accept-Api-Version: resource=4.0, protocol=2.1' \
--cookie 'iPlanetDirectoryPro={tokenId}' \
--data '{
    "userPassword": "generated-password",
    "thingType": "device",
    "thingKeys": "{\"keys\":[{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"alg\":\"ES256\",\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\"}]}"
}'
```

Run the simple example (`examples/thing/simple/main.go`):
```bash
./run.sh example "thing/simple" \
    -name "simple-thing" \
    -url "http://am.localtest.me:8080/am" \
    -realm "/" \
    -tree "auth-tree" \
    -keyfile "./examples/resources/eckey1.key.pem"
```
