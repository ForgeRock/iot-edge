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

package message

import (
	"bytes"
	"encoding/json"
)

// AuthenticatePayload represents the outbound and inbound data during an authentication request
type AuthenticatePayload struct {
	TokenID   string     `json:"tokenId,omitempty"`
	AuthID    string     `json:"authId,omitempty"`
	Callbacks []Callback `json:"callbacks,omitempty"`
}

// CommandRequestPayload represents the outbound data during a command request
type CommandRequestPayload struct {
	Command string `json:"command"`
}

func (p AuthenticatePayload) String() string {
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
