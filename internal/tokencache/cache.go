/*
 * Copyright 2020-2023 ForgeRock AS
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
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/patrickmn/go-cache"
)

// Cache for signed JSON Web Tokens
type Cache struct {
	store *cache.Cache
}

// New creates a new token cache
func New(defaultExpiration, cleanupInterval time.Duration) *Cache {
	return &Cache{store: cache.New(defaultExpiration, cleanupInterval)}
}

// unsafeClaimsOfAuthId deserialises the claims of the token without verifying them with the signature
func unsafeClaimsOfAuthId(rawToken string) (claims jwt.Claims, ok bool) {
	token, err := jwt.ParseSigned(rawToken)
	if err != nil {
		return claims, false
	}

	if err := token.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return claims, false
	}
	return claims, true
}

// Add the token with the cache with the given key
func (c *Cache) Add(key, token string) {
	// use expiry time in header if we are able to parse it, otherwise use default expiry time.
	claims, ok := unsafeClaimsOfAuthId(token)
	if ok && !claims.Expiry.Time().IsZero() {
		_ = c.store.Add(key, token, time.Until(claims.Expiry.Time()))
	} else {
		c.store.SetDefault(key, token)
	}
}

// Get a token from the cache
func (c *Cache) Get(key string) (token string, ok bool) {
	value, ok := c.store.Get(key)
	if !ok {
		return "", ok
	}
	token, ok = value.(string)
	return token, ok
}
