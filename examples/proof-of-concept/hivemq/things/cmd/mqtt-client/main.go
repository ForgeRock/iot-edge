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
	"flag"
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

	// ForgeRock connection information
	thingID := flag.String("name", "thingymabot", "Thing name")
	fqdn := flag.String("fqdn", "", "The FQDN of the ForgeOps deployment")
	flag.Parse()

	if *fqdn == "" {
		log.Fatal("FQDN must be provided")
	}

	store := secrets.Store{}
	signer, err := store.Signer(*thingID)
	if err != nil {
		log.Fatal(err)
	}
	certificates, err := store.Certificates(*thingID)
	if err != nil {
		log.Fatal(err)
	}
	keyID, _ := thing.JWKThumbprint(signer)
	amURL, err := url.Parse("https://" + *fqdn + "/am")
	if err != nil {
		log.Fatal(err)
	}

	// MQTT connection information
	// Can be retrieved from configuration
	server := "localhost:1883"
	qos := byte(2)
	topic := "test"

	dynamicThing, err := builder.Thing().
		ConnectTo(amURL).
		InRealm("/").
		WithTree("RegisterThings").
		AuthenticateThing(*thingID, "/", keyID, signer, nil).
		RegisterThing(certificates, nil).
		Create()

	if err != nil {
		log.Fatal(err)
	}
	log.Println(*thingID, " registration successful")

	connOpts := mqtt.NewClientOptions().
		AddBroker(server).
		SetCleanSession(true).
		SetClientID(*thingID)

	connOpts.SetCredentialsProvider(func() (username string, password string) {
		tokenResponse, err := dynamicThing.RequestAccessToken("publish", "subscribe")
		if err != nil {
			log.Fatal(err)
		}
		password, err = tokenResponse.AccessToken()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("Providing the OAuth 2.0 access token as password: %s", password)
		return *thingID, password
	})

	tlsConfig := &tls.Config{InsecureSkipVerify: true, ClientAuth: tls.NoClientCert}
	connOpts.SetTLSConfig(tlsConfig)
	connOpts.SetWill(topic, "Game Over", qos, false)

	client := mqtt.NewClient(connOpts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	fmt.Printf("Connected to %s\n", server)
	msgCount := 10
	for msgCount > 0 {
		msg := "Time now is " + time.Now().Format(time.RFC3339)
		if token := client.Publish(topic, qos, false, msg); token.Wait() && token.Error() != nil {
			log.Fatal(token.Error())
		}
		log.Printf("message \"%s\" sent", msg)
		msgCount--
		time.Sleep(time.Second * 2)
	}
	client.Disconnect(250)
}
