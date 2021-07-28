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
	"encoding/pem"
	"fmt"
	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"os"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

type confirmation struct {
	KID string `json:"kid,omitempty"`
}

type customClaims struct {
	Nonce string       `json:"nonce"`
	CNF   confirmation `json:"cnf,omitempty"`
}

func authJWT(signer crypto.Signer, subject, audience, kid, challenge string) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("typ", "JWT")
	alg, err := jws.JWAFromKey(signer)
	if err != nil {
		return "", err
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: cryptosigner.Opaque(signer)}, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).
		Claims(jwt.Claims{
			Subject:  subject,
			Audience: []string{audience},
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
		}).
		Claims(customClaims{
			Nonce: challenge,
			CNF:   confirmation{KID: kid},
		})
	response, err := builder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return response, nil
}

type commandlineOpts struct {
	Subject   string `short:"s" long:"subject" required:"true" description:"Subject, usually the Thing ID"`
	Audience  string `short:"a" long:"audience" required:"true" description:"Audience, usually the realm"`
	Challenge string `short:"c" long:"challenge" required:"true" description:"Challenge"`
	Keyfile   string `short:"k" long:"key" required:"true" description:"Private Key PEM"`
	KID       string `long:"kid" default:"pop.cnf" description:"Key ID"`
}

func main() {
	var opts commandlineOpts
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	b, err := ioutil.ReadFile(opts.Keyfile)
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

	signedJWT, err := authJWT(signer, opts.Subject, opts.Audience, opts.KID, opts.Challenge)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
