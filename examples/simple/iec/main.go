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
	"bufio"
	"flag"
	"fmt"
	"github.com/ForgeRock/iot-edge/pkg/iec"
	"log"
	"os"
)

var (
	amURL = flag.String("url", "http://openam.iectest.com:8080/openam", "AM URL")
	realm = flag.String("realm", "example", "AM Realm")
)

func simpleIEC() error {
	controller := iec.NewIEC(*amURL, *realm)

	err := controller.StartCOAPServer("127.0.0.1:5688")
	if err != nil {
		return err
	}
	defer controller.ShutdownCOAPServer()

	fmt.Println("IEC server started. Press a key to exit.")
	bufio.NewScanner(os.Stdin).Scan()
	return nil
}

func main() {
	flag.Parse()

	// pipe debug to standard out
	iec.DebugLogger.SetOutput(os.Stdout)

	if err := simpleIEC(); err != nil {
		log.Fatal(err)
	}
}
