package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
)

func Test_initialiseLoggerFailure(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "missingFilename", input: destFile},
		{name: "missingFilenameLeadingWhitespace", input: fmt.Sprintf("\t %s", destFile)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := initialiseLogger(tt.input)
			if err == nil {
				t.Fatal("Expected an error")
			}
		})
	}
}

func Test_initialiseLoggerSuccessSimple(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "none", input: destNone},
		{name: "stdout", input: destStdout},
		{name: "leadingWhitespace", input: fmt.Sprintf("\t %s", destStdout)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := initialiseLogger(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
		})
	}
}

func Test_initialiseLoggerDefaultToDiscard(t *testing.T) {
	tests := []struct {
		name, input string
	}{
		{name: "empty", input: ""},
		{name: "oddName", input: "boom"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, _, err := initialiseLogger(tt.input)
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
			w := l.Writer()
			if w != ioutil.Discard {
				t.Fatalf("Writing to %s instead of discarding", w)
			}
		})
	}
}

func Test_initialiseLoggerSuccessFile(t *testing.T) {
	tests := []struct {
		name, format, filename string
	}{
		{name: "toFile", format: destFile + " %s", filename: "tmp_test.log"},
		{name: "toFileOddWhitespace", format: fmt.Sprintf("\t%s    %%s", destFile), filename: "tmp_test.log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, f, err := initialiseLogger(fmt.Sprintf(tt.format, tt.filename))
			if err != nil {
				t.Fatalf("Unexpected error %s", err)
			}
			if f == nil {
				t.Fatal("Missing file")
			}
			f.Close()
			os.Remove(tt.filename)
		})
	}
}

// returns a map containing all the 'required' options with some demo values
func requiredOptions() map[string]string {
	return map[string]string{
		optEndpoint:     "http://am.iec.com:8080/openam/oauth2/realms/root/realms/edge/introspect",
		optClientID:     "client_id",
		optClientSecret: "changeit",
	}
}
func Test_initialiseUserDataMissingOpt(t *testing.T) {
	tests := []struct {
		missingOpt string
	}{
		{missingOpt: optEndpoint},
		{missingOpt: optClientID},
		{missingOpt: optClientSecret},
	}

	for _, tt := range tests {
		t.Run(tt.missingOpt, func(t *testing.T) {
			opts := requiredOptions()
			delete(opts, tt.missingOpt)
			_, err := initialiseUserData(opts)
			if err == nil {
				t.Fatalf("Expected an error")
			}
		})
	}
}

func Test_initialiseUserDataCheckMappingStrings(t *testing.T) {
	testOpts := requiredOptions()
	tests := []struct {
		field, expectVal string
	}{
		{field: "endpoint", expectVal: testOpts[optEndpoint]},
		{field: "clientID", expectVal: testOpts[optClientID]},
		{field: "clientSecret", expectVal: testOpts[optClientSecret]},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			data, err := initialiseUserData(testOpts)
			if err != nil {
				t.Fatalf("Unexpected error, %s", err)
			}
			val := reflect.Indirect(reflect.ValueOf(data))
			structVal := val.FieldByName(tt.field).String()
			if structVal != tt.expectVal {
				t.Fatalf("Expected %s got %s", tt.expectVal, structVal)
			}
		})
	}
}
