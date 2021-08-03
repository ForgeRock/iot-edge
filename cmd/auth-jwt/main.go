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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	frcrypto "github.com/ForgeRock/iot-edge/v7/internal/crypto"
	"github.com/ForgeRock/iot-edge/v7/internal/jws"
	"github.com/jessevdk/go-flags"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type confirmation struct {
	KID string           `json:"kid,omitempty"`
	JWK *jose.JSONWebKey `json:"jwk,omitempty"`
}

type customClaims struct {
	Nonce     string       `json:"nonce"`
	CNF       confirmation `json:"cnf,omitempty"`
	ThingType string       `json:"thingType,omitempty"`
}

func authJWT(key crypto.Signer, subject, audience string, claims customClaims) (string, error) {
	opts := &jose.SignerOptions{}
	alg, err := jws.JWAFromKey(key)
	if err != nil {
		return "", err
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
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
		Claims(claims)
	return builder.CompactSerialize()
}

type commandlineOpts struct {
	Subject     string `short:"s" long:"subject" required:"true" description:"Subject, usually the Thing ID"`
	Audience    string `short:"a" long:"audience" required:"true" description:"Audience, usually the realm"`
	Challenge   string `short:"c" long:"challenge" required:"true" description:"Challenge"`
	Keyfile     string `short:"k" long:"key" required:"true" description:"Private Key PEM"`
	KID         string `long:"kid" default:"pop.cnf" description:"Key ID"`
	Certificate string `long:"certificate" description:"Thing Certificate"`
	ThingType   string `long:"type" default:"device" choice:"device" choice:"service" choice:"gateway" description:"Thing Type"`
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
		log.Fatal("failed to decode PEM block containing private key")
	}

	signer, err := frcrypto.ParsePEM(block)
	if err != nil {
		log.Fatal(err)
	}

	claims := customClaims{Nonce: opts.Challenge}
	if opts.Certificate != "" {
		b, err := ioutil.ReadFile(opts.Certificate)
		if err != nil {
			log.Fatal(err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			log.Fatal("unable to decode certificate")
		}
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			log.Fatal(err)
		}
		claims.CNF.JWK = &jose.JSONWebKey{
			Key:          signer.Public(),
			Certificates: certs,
			KeyID:        opts.KID,
			Use:          "sig",
		}
		claims.ThingType = opts.ThingType
	} else {
		claims.CNF.KID = opts.KID
	}

	signedJWT, err := authJWT(signer, opts.Subject, opts.Audience, claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print(signedJWT)
}
