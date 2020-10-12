package main

import (
	"strings"
)

const (
	levelSep    = "/"
	multiLevel  = "#"
	singleLevel = "+"
)

// returns true if the MQTT topic filter matches the topic name
func matchTopic(filter, name string) bool {
	// split both strings into a root level and a remainder
	f := strings.SplitN(filter, levelSep, 2)
	n := strings.SplitN(name, levelSep, 2)

	// check whether the root levels match
	switch f[0] {
	case multiLevel:
		return true
	case n[0], singleLevel:
		// roots match, continue
		break
	default:
		// roots do not match
		return false
	}

	// check whether the filter or name consists of a single level
	switch {
	case len(f) == 1 && len(n) == 1:
		return true
	case len(f) == 1:
		return false
	case len(n) == 1:
		if f[1] == multiLevel {
			// special case is when filter has 1 extra level which is the '#' character
			return true
		}
		return false

	}
	return matchTopic(f[1], n[1])
}
