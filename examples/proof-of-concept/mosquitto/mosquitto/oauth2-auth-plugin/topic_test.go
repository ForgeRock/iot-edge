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

package main

import (
	"fmt"
	"testing"
)

type matchTest struct {
	name, filter, topic string
	isMatch             bool
}

func (m matchTest) expect() string {
	s := "MATCH"
	if !m.isMatch {
		s = "NOT matchTopic"
	}
	return fmt.Sprintf("Expected filter %s, topic %s to %s", m.filter, m.topic, s)
}

// tests based on non-normative comments in the MQTT spec v5.0
// http://docs.oasis-open.org/mqtt/mqtt/v5.0/cs02/mqtt-v5.0-cs02.pdf
func Test_match(t *testing.T) {
	tests := []matchTest{
		{name: "simple1", filter: "/", topic: "/", isMatch: true},
		{name: "simple2", filter: "sport", topic: "sport", isMatch: true},
		{name: "simple3", filter: "sport/tennis/player1", topic: "sport/tennis/player1", isMatch: true},
		{name: "simple4", filter: "sport/tennis/player1", topic: "sport/tennis/player2", isMatch: false},
		// A leading or trailing ‘/’ creates a distinct Topic Name or Topic Filter
		{name: "simple5", filter: "/sport", topic: "sport", isMatch: false},
		{name: "simple6", filter: "sport", topic: "/sport", isMatch: false},
		{name: "simple7", filter: "sport/", topic: "sport", isMatch: false},
		{name: "simple8", filter: "sport", topic: "sport/", isMatch: false},
		// Topic Names and Topic Filters are case sensitive
		{name: "simple9", filter: "sport", topic: "Sport", isMatch: false},

		// “#” is a valid filter and will receive every Application Message
		{name: "hash1", filter: "#", topic: "sport", isMatch: true},
		{name: "hash2", filter: "#", topic: "sport/tennis/player1", isMatch: true},
		{name: "hash3", filter: "#", topic: "sport/tennis/player1/ranking", isMatch: true},
		{name: "hash4", filter: "#", topic: "sport/tennis/player1/score/wimbledon", isMatch: true},
		// # includes the parent level
		{name: "hash5", filter: "sport/tennis/player1/#", topic: "sport/tennis/player1", isMatch: true},
		{name: "hash6", filter: "sport/tennis/player1/#", topic: "sport/tennis/player1/ranking", isMatch: true},
		{name: "hash7", filter: "sport/tennis/player1/#", topic: "sport/tennis/player1/score/wimbledon", isMatch: true},

		{name: "plus1", filter: "+", topic: "sport", isMatch: true},
		{name: "plus2", filter: "+", topic: "sport/tennis/player1", isMatch: false},
		{name: "plus3", filter: "+", topic: "sport/tennis/player1/ranking", isMatch: false},
		{name: "plus4", filter: "sport/+/player1", topic: "sport/tennis/player1", isMatch: true},
		{name: "plus5", filter: "sport/+/player1", topic: "sport/rugby/player1", isMatch: true},
		{name: "plus6", filter: "sport/+/player1", topic: "sport/rugby/player1/score", isMatch: false},
		{name: "plus7", filter: "+", topic: "/finance", isMatch: false},
		{name: "plus8", filter: "/+", topic: "/finance", isMatch: true},
		{name: "plus9", filter: "+/+", topic: "/finance", isMatch: true},
		{name: "plus10", filter: "sport/+", topic: "sport", isMatch: false},
		{name: "plus11", filter: "sport/+", topic: "sport/", isMatch: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := matchTopic(tt.filter, tt.topic)
			if m != tt.isMatch {
				t.Fatal(tt.expect())
			}
		})
	}
}
