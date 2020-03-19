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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

// authenticatePayload represents the outbound and inbound data during an authentication request
type authenticatePayload struct {
	TokenID   string     `json:"tokenId,omitempty"`
	AuthID    string     `json:"authId,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
}

func (p authenticatePayload) String() string {
	b, err := json.Marshal(p)
	if err != nil {
		return ""
	}

	var out bytes.Buffer
	err = json.Indent(&out, b, "", "\t")
	if err != nil {
		return ""
	}
	return out.String()
}

// Client is an interface that describes the connection to the ForgeRock platform
type Client interface {
	// authenticate sends an authenticate request to the ForgeRock platform
	authenticate(ctx context.Context, request authenticatePayload) (response authenticatePayload, err error)
}

// AMClient contains information for connecting directly to AM
type AMClient struct {
	AuthURL string
}

func (c AMClient) authenticate(_ context.Context, payload authenticatePayload) (reply authenticatePayload, err error) {
	client := &http.Client{}
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return reply, err
	}
	request, err := http.NewRequest(http.MethodPost, c.AuthURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return reply, err
	}
	request.Header.Add("Accept-API-Version", "protocol=1.0,resource=2.1")
	request.Header.Add("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return reply, err
	}
	defer response.Body.Close()
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return reply, err
	}
	if response.StatusCode != http.StatusOK {
		return reply, fmt.Errorf("received %v, %s", response.StatusCode, string(responseBody))
	}
	if err = json.Unmarshal(responseBody, &reply); err != nil {
		return reply, err
	}
	return reply, err
}

// Thing represents an AM Thing identity
type Thing struct {
	Client   Client
	Handlers []CallbackHandler
}

// authenticate the Thing
func (t Thing) authenticate(ctx context.Context) (tokenID string, err error) {
	payload := authenticatePayload{}
	for {
		select {
		case <-ctx.Done():
			return tokenID, errors.New("authenticate: context done")
		default:
			if payload, err = t.Client.authenticate(ctx, payload); err != nil {
				return tokenID, err
			}

			if payload.TokenID != "" {
				return payload.TokenID, nil
			}
			if err = processCallbacks(payload.Callbacks, t.Handlers); err != nil {
				return tokenID, err
			}
		}
	}
}

// Initialise the Thing
func (t Thing) Initialise(ctx context.Context) (err error) {
	_, err = t.authenticate(ctx)
	return err
}
