/*
 * Copyright 2022-2023 ForgeRock AS
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

package jwtutil

import (
	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

// SoftwareStatement creates a signed software statement containing the given issuer and client JWK. Additional claims
// can be added via the claims function.
func SoftwareStatement(iss string, clientJWK jose.JSONWebKey, claims func() interface{}) (string, error) {
	swPublisherStore := secrets.Store{Path: "./resources/example.secrets"}
	swPublisherKey, _ := swPublisherStore.Signer("software-publisher")
	swPublisherKid, _ := thing.JWKThumbprint(swPublisherKey)

	opts := &jose.SignerOptions{}
	opts.WithHeader("alg", "ES256")
	opts.WithHeader("kid", swPublisherKid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: swPublisherKey}, opts)
	if err != nil {
		return "", err
	}
	keySet := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{clientJWK},
	}
	jwtBuilder := jwt.Signed(signer).Claims(struct {
		Issuer string             `json:"iss"`
		JWKS   jose.JSONWebKeySet `json:"jwks"`
	}{
		Issuer: iss,
		JWKS:   keySet,
	})
	if claims != nil {
		jwtBuilder = jwtBuilder.Claims(claims())
	}
	response, err := jwtBuilder.CompactSerialize()
	if err != nil {
		return "", err
	}
	return response, err
}
