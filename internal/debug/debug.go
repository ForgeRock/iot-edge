/*
 * Copyright 2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package debug

import (
	"log"
	"net/http"
	"net/http/httputil"
)

// WriteRequest will dump the given request and response and prints the result to the configured writer
func WriteRequest(logger *log.Logger, req *http.Request, res *http.Response) {
	if req != nil {
		dump, err := httputil.DumpRequest(req, true)
		if err != nil {
			dump, err = httputil.DumpRequest(req, false)
		}
		message := "*** HTTP Request ***\n"
		if err == nil {
			message += string(dump)
		} else {
			message += "Failed to dump request: " + err.Error()
		}
		logger.Println(message)
	}

	if res != nil {
		dump, err := httputil.DumpResponse(res, true)
		if err != nil {
			dump, err = httputil.DumpResponse(res, false)
		}
		message := "*** HTTP Response ***\n"
		if err == nil {
			message += string(dump)
		} else {
			message += "Failed to dump response: " + err.Error()
		}
		logger.Println(message)
	}
}
