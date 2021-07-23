/*
 * Copyright 2021 ForgeRock AS
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
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"

	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/jessevdk/go-flags"
	"gopkg.in/square/go-jose.v2"
)

type commandlineOpts struct {
	In  string `long:"in" required:"true" description:"Things Endpoint Version"`
	Out string `long:"pubout" required:"true" description:"Things URL"`
}

func main() {
	var opts commandlineOpts
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	b, err := ioutil.ReadFile(opts.In)
	if err != nil {
		log.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatal("failed to decode PEM block containing public key")
	}
	signer, err := frcrypto.ParsePEM(block)
	if err != nil {
		log.Fatal(err)
	}
	jwks, err := json.Marshal(
		jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{
				{
					Key:   signer.Public(),
					KeyID: "test",
					Use:   "sig",
				},
			},
		})
	err = ioutil.WriteFile(opts.Out, jwks, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
}
