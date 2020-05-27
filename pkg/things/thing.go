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

package things

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
	"io/ioutil"
	"log"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var DebugLogger = log.New(ioutil.Discard, "", 0)

var (
	ErrUnauthorised = errors.New("unauthorised")
)

// Client is an interface that describes the connection to the ForgeRock platform
type Client interface {
	// Initialise the client. Must be called before the Client is used by a Thing
	Initialise() error

	// Authenticate sends an Authenticate request to the ForgeRock platform
	Authenticate(payload AuthenticatePayload) (reply AuthenticatePayload, err error)

	// AMInfo returns the information required to construct valid signed JWTs
	AMInfo() (info AMInfoSet, err error)

	// SendCommand sends the signed JWT to the IoT Command Endpoint
	SendCommand(tokenID string, jws string) (reply []byte, err error)
}

// ThingType describes the Thing type
type ThingType string

const (
	TypeDevice ThingType = "device"
	TypeIEC    ThingType = "iec"
)

// SigningKey describes a key used for signing messages sent to AM
type SigningKey struct {
	KID    string
	Signer crypto.Signer
}

// Thing represents an AM Thing identity
// Restrictions: confirmationKey uses ECDSA with a P-256, P-384 or P-512 curve. Sign returns the signature ans1 encoded.
type Thing struct {
	Client          Client
	confirmationKey SigningKey // see restrictions
	handlers        []Handler
	thingType       ThingType
}

// NewThing creates a new Thing
func NewThing(client Client, confirmationKey SigningKey, handlers []Handler) *Thing {
	return &Thing{
		Client:          client,
		confirmationKey: confirmationKey,
		handlers:        handlers,
		thingType:       TypeDevice,
	}
}

// authenticate the Thing
func (t *Thing) authenticate() (tokenID string, err error) {
	auth := AuthenticatePayload{}
	for {
		if auth, err = t.Client.Authenticate(auth); err != nil {
			return tokenID, err
		}

		if auth.HasSessionToken() {
			return auth.TokenId, nil
		}
		if err = ProcessCallbacks(t, t.handlers, auth.Callbacks); err != nil {
			return tokenID, err
		}
	}
}

// Initialise the Thing
func (t *Thing) Initialise() (err error) {
	if t.confirmationKey.KID == "" {
		t.confirmationKey.KID, err = createKID(t.confirmationKey.Signer)
		if err != nil {
			return err
		}
	}
	err = t.Client.Initialise()
	if err != nil {
		return err
	}
	_, err = t.authenticate()
	return err
}

func signedJWTBody(signer crypto.Signer, url, version, tokenID string, body interface{}) (string, error) {
	opts := &jose.SignerOptions{}
	opts.WithHeader("aud", url)
	opts.WithHeader("api", version)
	// Note: nonce can be 0 as long as we create a new session for each request. If we reuse the token we need
	// to increment the nonce between requests
	opts.WithHeader("nonce", 0)

	// check that the signer is supported
	alg, err := signingJWAFromKey(signer)
	if err != nil {
		return "", err
	}

	// create a jose.OpaqueSigner from the crypto.Signer
	opaque := cryptosigner.Opaque(signer)

	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: opaque}, opts)
	if err != nil {
		return "", err
	}
	builder := jwt.Signed(sig).Claims(sendCommandClaims{CSRF: tokenID})
	if body != nil {
		builder = builder.Claims(body)
	}
	return builder.CompactSerialize()
}

// RequestAccessToken requests an OAuth 2.0 access token for a thing. The provided scopes will be included in the token
// if they are configured in the thing's associated OAuth 2.0 Client in AM. If no scopes are provided then the token
// will include the default scopes configured in the OAuth 2.0 Client.
func (t *Thing) RequestAccessToken(scopes ...string) (response AccessTokenResponse, err error) {
	tokenID, err := t.authenticate()
	if err != nil {
		return
	}
	info, err := t.Client.AMInfo()
	if err != nil {
		return
	}
	requestBody, err := signedJWTBody(t.confirmationKey.Signer, info.IoTURL, info.IoTVersion, tokenID, NewGetAccessTokenV1(scopes))
	if err != nil {
		return
	}
	reply, err := t.Client.SendCommand(tokenID, requestBody)
	if reply != nil {
		DebugLogger.Println("RequestAccessToken response: ", string(reply))
	}
	if err != nil {
		return
	}
	err = json.Unmarshal(reply, &response.Content)
	DebugLogger.Println("RequestAccessToken request completed successfully")
	return
}

// Realm returns the Thing's AM realm
func (t *Thing) Realm() string {
	info, err := t.Client.AMInfo()
	if err != nil {
		DebugLogger.Println(err)
	}
	return info.Realm
}

// Type returns the Thing's type
func (t *Thing) Type() ThingType {
	return t.thingType
}

// ConfirmationKey returns the Thing's confirmation signing key
func (t *Thing) ConfirmationKey() SigningKey {
	return t.confirmationKey
}

// createKID creates a key ID for a signer
func createKID(key crypto.Signer) (string, error) {
	thumbprint, err := (&jose.JSONWebKey{Key: key.Public()}).Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(thumbprint), nil
}

// SetConfirmationKey sets the Thing's confirmation key
func (t *Thing) SetConfirmationKey(key SigningKey) (err error) {
	if key.KID == "" {
		key.KID, err = createKID(key.Signer)
		if err != nil {
			return err
		}
	}
	t.confirmationKey = key
	return nil
}
