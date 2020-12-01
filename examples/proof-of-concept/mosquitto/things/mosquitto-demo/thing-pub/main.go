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
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ForgeRock/iot-edge/v7/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	mqtt "github.com/eclipse/paho.mqtt.golang"
)

func main() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	thing.SetDebugLogger(log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Llongfile))

	// ForgeRock connection information
	thingID := flag.String("name", "47cf707c-80c1-4816-b067-99db2a443113", "Thing name")
	flag.Parse()

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
	amURL, _ := url.Parse(os.Getenv("AM_URL"))
	amRealm := os.Getenv("AM_REALM")
	amTree := os.Getenv("AM_TREE")

	// MQTT connection information
	// Can be retrieved from configuration
	server := os.Getenv("MQTT_SERVER_URL")
	qos := byte(2)
	topic := "test"

	dynamicThing, err := builder.Thing().
		ConnectTo(amURL).
		InRealm(amRealm).
		WithTree(amTree).
		AuthenticateThing(*thingID, amRealm, keyID, signer, nil).
		RegisterThing(certificates, nil).
		Create()

	if err != nil {
		log.Fatal(err)
	}
	log.Println(*thingID, " registration successful")

	connOpts := mqtt.NewClientOptions().
		AddBroker(server).
		SetCleanSession(true)

	connOpts.SetCredentialsProvider(func() (username string, password string) {
		tokenResponse, err := dynamicThing.RequestAccessToken("mqtt.write:#")
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
	connOpts.SetClientID("thing-pub")

	client := mqtt.NewClient(connOpts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}

	fmt.Printf("Connected to %s\n", server)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	go func() {
		i := 1
		var msg string
		for {
			switch {
			case i%35 == 0:
				msg = "fizz-buzz"
			case i%5 == 0:
				msg = "fizz"
			case i%7 == 0:
				msg = "buzz"
			default:
				msg = fmt.Sprintf("%d", i)
			}
			if token := client.Publish(topic, qos, false, msg); token.Wait() && token.Error() != nil {
				log.Fatal(token.Error())
			}
			log.Printf("message \"%s\" sent", msg)

			select {
			case <-ticker.C:
				i++
			case <-c:
				break
			}
		}
	}()

	<-c
}
