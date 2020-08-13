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

package tokencache

import (
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// check that the token is stored only for as long as the expiry time in the header
func TestTokenCache_Add_Expiry(t *testing.T) {
	expiry := time.Now().Add(time.Minute + 11*time.Second).Round(time.Second)
	key := []byte("secret")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}

	cl := jwt.Claims{
		Expiry: jwt.NewNumericDate(expiry),
	}
	token, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}

	cache := New(5*time.Minute, 10*time.Minute)
	cache.Add("1", token)
	_, cacheExpiry, ok := cache.store.GetWithExpiration("1")
	if !ok {
		t.Fatal("The token has not been stored")
	}
	// check that expiry values are the same
	// we have to round due to loss of precision in the jwt building/parsing
	if expiry != cacheExpiry.Round(time.Second) {
		t.Errorf("Token expiry %v hasn't been used for store expiry %v", expiry, cacheExpiry)
	}

}
