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
