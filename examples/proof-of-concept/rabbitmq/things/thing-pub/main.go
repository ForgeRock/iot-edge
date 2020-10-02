/*
 * Copyright 2020 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ForgeRock/iot-edge/v7/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	//thing.SetDebugLogger(log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Llongfile))

	// Provided
	thingID := "47cf707c-80c1-4816-b067-99db2a443113"
	signer := secrets.Signer(thingID)
	certificate := []*x509.Certificate{secrets.Certificate(thingID, signer.Public())}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, _ := url.Parse(os.Getenv("AM_URL"))
	server := os.Getenv("MQTT_SERVER_URL")
	qos := 2

	dynamicThing, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(thingID, "/", keyID, signer, nil).
		RegisterThing(certificate, nil).
		Create()

	if err != nil {
		log.Fatal(err)
	}
	log.Println(thingID, " registration successful")

	connOpts := mqtt.NewClientOptions().
		AddBroker(server).
		SetCleanSession(true)

	connOpts.SetCredentialsProvider(func() (username string, password string) {
		tokenResponse, err := dynamicThing.RequestAccessToken(
			"forgerock-iot-oauth2-client.write:*/*/*",
			"forgerock-iot-oauth2-client.configure:*/*")
		if err != nil {
			log.Fatal(err)
		}
		password, err = tokenResponse.AccessToken()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Providing the OAuth 2.0 access token as password: %s", password)
		return thingID, password
	})

	tlsConfig := &tls.Config{InsecureSkipVerify: true, ClientAuth: tls.NoClientCert}
	connOpts.SetTLSConfig(tlsConfig)

	client := mqtt.NewClient(connOpts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	fmt.Printf("Connected to %s\n", server)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	i := 10
	for i > 0 {
		select {
		case <-ticker.C:
			msg := fmt.Sprintf("T-minus %d", i)
			i--
			if token := client.Publish("test", byte(qos), true, msg); token.Wait() && token.Error() != nil {
				log.Fatal(token.Error())
			}
			log.Printf("message \"%s\" sent", msg)
		case <-c:
			break
		}
	}
}
