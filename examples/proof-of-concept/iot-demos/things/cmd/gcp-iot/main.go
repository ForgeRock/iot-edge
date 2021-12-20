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
	"bytes"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jessevdk/go-flags"
	"github.com/jpillora/backoff"

	"github.com/ForgeRock/iot-edge/examples/secrets"
	"github.com/ForgeRock/iot-edge/v7/pkg/builder"
	"github.com/ForgeRock/iot-edge/v7/pkg/thing"
)

// createJWT creates a JWT for authorising with GCP IoT.
// Assumes the signing key is a ES256 key.
func createJWT(projectID string, signer crypto.Signer) (string, error) {
	claims := jwt.StandardClaims{
		Audience:  projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod("ES256"), claims)

	return token.SignedString(signer)
}

type binaryData struct {
	BinaryData string `json:"binary_data"`
}

type statusPayload struct {
	State binaryData `json:"state"`
}

// createStateRequest creates an HTTP request for publishing the state of a device.
func createStateRequest(url, jwt, status string) (*http.Request, error) {
	payload := statusPayload{
		State: binaryData{
			BinaryData: base64.StdEncoding.EncodeToString([]byte(status)),
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwt))
	return request, nil
}

type commandlineOpts struct {
	URL         string `long:"url" default:"https://iot.iam.example.com/am" description:"AM URL"`
	Realm       string `long:"realm" default:"/" description:"AM Realm"`
	Audience    string `long:"audience" default:"/" description:"JWT Audience"`
	Tree        string `long:"tree" default:"RegisterThings" description:"Authentication tree"`
	Name        string `short:"n" long:"name" required:"true" description:"Device name"`
	SecretStore string `long:"secrets" description:"Path to pre-created secret store"`
	ProjectID   string `short:"p" required:"true" description:"Google Cloud Platform Project ID"`
	Location    string `short:"l" required:"true" description:"IoT Core Device Registry Region"`
	RegistryID  string `short:"r" required:"true" description:"IoT Core Device Registry ID"`
	Debug       bool   `short:"d" description:"Debug"`
}

// registerAndUpdateState registers a Thing with AM and then publishes its state to the GCP IoT HTTP Bridge.
func registerAndUpdateState() (err error) {
	var opts commandlineOpts
	_, err = flags.Parse(&opts)
	if err != nil {
		return err
	}

	u, err := url.Parse(opts.URL)
	if err != nil {
		return err
	}

	store := secrets.Store{Path: opts.SecretStore}
	signer, err := store.Signer(opts.Name)
	if err != nil {
		return err
	}
	certs, err := store.Certificates(opts.Name)
	if err != nil {
		return err
	}

	// use key thumbprint as key id
	keyID, err := thing.JWKThumbprint(signer)
	if err != nil {
		return err
	}

	builder := builder.Thing().
		ConnectTo(u).
		InRealm(opts.Realm).
		WithTree(opts.Tree).
		AuthenticateThing(opts.Name, opts.Audience, keyID, signer, nil).
		RegisterThing(certs, nil)

	fmt.Println("--> Register & Authenticate", opts.Name)
	_, err = builder.Create()
	if err != nil {
		return err
	}
	fmt.Println("--> Registered & Authenticated successfully")

	for {
		fmt.Printf("--> Please enter a \"state\" for %s to publish to GCP: ", opts.Name)
		var input string
		fmt.Scanln(&input)
		url := fmt.Sprintf(
			"https://cloudiotdevice.googleapis.com/v1/projects/%s/locations/%s/registries/%s/devices/%s:setState",
			opts.ProjectID,
			opts.Location,
			opts.RegistryID,
			opts.Name)

		b := &backoff.Backoff{
			Min:    time.Second,
			Max:    20 * time.Second,
			Jitter: true,
		}

		var request *http.Request
		var response *http.Response
		for i := 0; i < 10; i++ {
			fmt.Print(".")
			jwt, err := createJWT(opts.ProjectID, signer)
			if err != nil {
				return err
			}

			request, err = createStateRequest(url, jwt, input)
			if err != nil {
				return err
			}
			response, err = http.DefaultClient.Do(request)
			if err == nil && response.StatusCode == http.StatusOK {
				break
			}
			time.Sleep(b.Duration())
		}
		fmt.Println()

		if err != nil {
			return err
		} else if response.StatusCode != http.StatusOK {
			if opts.Debug {
				req, _ := httputil.DumpRequest(request, true)
				res, _ := httputil.DumpResponse(response, true)
				fmt.Printf("%s\n\n%s\n\n", req, res)
			}
			return fmt.Errorf("unexpected status %v", response.StatusCode)
		}
		fmt.Println("--> State published successfully")
	}

	return nil
}

func main() {
	// pipe debug to standard out
	thing.DebugLogger().SetOutput(os.Stdout)

	if err := registerAndUpdateState(); err != nil {
		log.Fatal(err)
	}
}
