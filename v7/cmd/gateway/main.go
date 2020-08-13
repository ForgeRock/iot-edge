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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ForgeRock/iot-edge/v7/internal/gateway"
	"github.com/ForgeRock/iot-edge/v7/pkg/callback"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/jessevdk/go-flags"
)

func loadKey(filename string) (crypto.Signer, error) {
	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("unable to decode key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privateKey.(crypto.Signer), nil
}

func loadCertificates(filename string) ([]*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	return x509.ParseCertificates(block.Bytes)
}

type commandlineOpts struct {
	URL      string `long:"url" required:"true" description:"AM URL"`
	Realm    string `long:"realm" description:"AM Realm"`
	Audience string `long:"audience" required:"true" description:"JWT Audience"`
	Tree     string `long:"tree" required:"true" description:"Authentication tree"`
	Name     string `long:"name" required:"true" description:"Gateway name"`
	Address  string `long:"address" required:"true" description:"CoAP Address of Gateway"`
	KeyFile  string `long:"key" required:"true" description:"The file containing the Gateway's signing key"`
	KeyID    string `long:"kid" description:"The Gateway's signing key ID"`
	CertFile string `long:"cert" description:"The file containing the Gateway's certificate"`
	// see time.ParseDuration for valid timeout strings
	Timeout time.Duration `long:"timeout" default:"5s" description:"Timeout for AM communications"`
	Debug   bool          `short:"d" long:"debug" description:"Switch on debug"`
}

func (o commandlineOpts) String() string {
	return fmt.Sprintf(
		`commandline options
	url: %s
	realm: %s
	tree: %s
	name: %s
	address: %s
	key: %s
	kid: %s
	certificate: %s
	timeout %v
	debug: %v`,
		o.URL, o.Realm, o.Tree, o.Name, o.Address, o.KeyFile, o.KeyID, o.CertFile, o.Timeout, o.Debug)
}

// runGateway initialises and runs a Thing Gateway
func runGateway() error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var opts commandlineOpts
	_, err := flags.Parse(&opts)
	if err != nil {
		return err
	}
	fmt.Printf("%v\n", opts)

	if opts.Debug {
		// pipe debug to standard out
		thing.SetDebugLogger(log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds|log.Llongfile))
	}

	amKey, err := loadKey(opts.KeyFile)
	if err != nil {
		return err
	}

	if opts.KeyID == "" {
		opts.KeyID, err = thing.JWKThumbprint(amKey)
		if err != nil {
			return err
		}
	}

	callbacks := []callback.Handler{
		callback.AuthenticateHandler{
			Audience: opts.Audience,
			ThingID:  opts.Name,
			KeyID:    opts.KeyID,
			Key:      amKey,
		}}
	if opts.CertFile != "" {
		certs, err := loadCertificates(opts.CertFile)
		if err != nil {
			return err
		}
		callbacks = append(callbacks, callback.RegisterHandler{
			Audience:     opts.Audience,
			ThingID:      opts.Name,
			ThingType:    callback.TypeGateway,
			KeyID:        opts.KeyID,
			Key:          amKey,
			Certificates: certs,
		})

	}
	thingGateway := gateway.NewThingGateway(opts.URL, opts.Realm, opts.Tree, opts.Timeout, callbacks)

	err = thingGateway.Initialise()
	if err != nil {
		return err
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	err = thingGateway.StartCOAPServer(opts.Address, serverKey)
	if err != nil {
		return err
	}
	defer thingGateway.ShutdownCOAPServer()

	fmt.Println("Thing Gateway server started.")
	<-signals
	fmt.Println("Thing Gateway server shutting down.")
	return nil
}

func main() {
	if err := runGateway(); err != nil {
		log.Fatal(err)
	}
}
