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
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"github.com/jessevdk/go-flags"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func createThingJWT(key crypto.Signer, url string, version string, n int64, custom map[string]interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	opts.WithHeader("nonce", n)

	alg, err := jws.JWAFromKey(key)
	if err != nil {
		return "", err
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)

	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).Claims(custom)
	return builder.CompactSerialize()
}

type commandlineOpts struct {
	Version string `long:"version" default:"protocol=2.0,resource=1.0" description:"Things Endpoint Version"`
	URL     string `short:"u" long:"url" required:"true" description:"Things URL"`
	Nonce   int64  `short:"n" long:"nonce" default:"-1" description:"Nonce"`
	Keyfile string `short:"k" long:"key" required:"true" description:"Private Key PEM"`
	Custom  string `long:"custom" default:"{}" description:"Custom Claims"`
}

func main() {
	var opts commandlineOpts
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatal(err)
	}

	var custom map[string]interface{}
	err = json.Unmarshal([]byte(opts.Custom), &custom)
	if err != nil {
		log.Fatalf("%v `%s`", err, opts.Custom)
	}

	b, err := ioutil.ReadFile(opts.Keyfile)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(b)
	if block == nil {
		log.Fatal("failed to decode PEM block containing private key")
	}

	signer, err := frcrypto.ParsePEM(block)
	if err != nil {
		log.Fatal(err)
	}

	n := opts.Nonce
	if n == -1 {
		// if no nonce has been supplied, use unix time
		n = time.Now().Unix()
	}

	signedJWT, err := createThingJWT(signer, opts.URL, opts.Version, n, custom)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
