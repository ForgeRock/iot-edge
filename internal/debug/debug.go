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

package debug

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"

	"github.com/go-ocf/go-coap"
)

// All SDK debug information is written to this Logger. The logger is muted by default. To see the debug output assign
// your own logger (or a new one) to this variable.
var Logger = log.New(io.Discard, "", 0)

// DumpHTTPRoundTrip will dump the given HTTP request and response
func DumpHTTPRoundTrip(req *http.Request, res *http.Response) (message string) {
	if req != nil {
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			dump, err = httputil.DumpRequest(req, false)
		}
		message = "*** HTTP Request ***\n"
		if err == nil {
			message += string(dump)
		} else {
			message += "Failed to dump request: " + err.Error()
		}
	}

	if res != nil {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			dump, err = httputil.DumpResponse(res, false)
		}
		message += "*** HTTP Response ***\n"
		if err == nil {
			message += string(dump)
		} else {
			message += "Failed to dump response: " + err.Error()
		}
	}
	return message
}

// dumpCOAPMessage will dump the COAP message
func dumpCOAPMessage(msg coap.Message) (dump string) {
	if len(msg.Path()) > 0 {
		dump += fmt.Sprintf("Path: %v\n", msg.PathString())
	}
	if len(msg.Query()) > 0 {
		dump += fmt.Sprintf("Query: %v\n", msg.QueryString())
	}
	dump += fmt.Sprintf("Type: %v\n", msg.Type())
	dump += fmt.Sprintf("Code: %v\n", msg.Code())
	dump += fmt.Sprintf("Messsage ID: %v\n", msg.MessageID())
	dump += fmt.Sprintf("Token: %x\n", string(msg.Token()))
	if msg.AllOptions().Len() > 0 {
		dump += fmt.Sprintf("Options: %v\n", msg.AllOptions())
	}
	dump += fmt.Sprintf("\nPayload:\n%v\n", string(msg.Payload()))
	return dump
}

// DumpCOAPRoundTrip will dump the given COAP connection, request message and response message
func DumpCOAPRoundTrip(conn *coap.ClientConn, req coap.Message, res coap.Message) (message string) {
	if conn != nil {
		message += fmt.Sprintf("\nCONNECTION: %s\n", conn.LocalAddr())
	}
	if req != nil {
		message += "\n*** COAP Request ***\n"
		message += dumpCOAPMessage(req)
	}
	if res != nil {
		message += "\n*** COAP Response ***\n"
		message += dumpCOAPMessage(res)
	}
	return message
}
