/*
 * Copyright 2022 ForgeRock AS
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
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type SubSchema struct {
	XMLName         xml.Name          `xml:"SubSchema"`
	AttributeSchema []AttributeSchema `xml:"AttributeSchema"`
}

type AttributeSchema struct {
	XMLName      xml.Name `xml:"AttributeSchema"`
	Name         string   `xml:"name,attr"`
	ResourceName string   `xml:"resourceName,attr"`
}

func sanitiseName(name string) string {
	return "oauth-client-" + strings.ReplaceAll(strings.ReplaceAll(name, "_", "-"), ".", "-")
}

func main() {
	xmlFile, err := os.Open("sms.xml")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Successfully Opened sms.xml")
	defer xmlFile.Close()
	byteValue, _ := ioutil.ReadAll(xmlFile)
	var subSchema SubSchema
	err = xml.Unmarshal(byteValue, &subSchema)
	if err != nil {
		log.Fatal(err)
	}

	sanitisedNames := map[string]string{}

	for _, attr := range subSchema.AttributeSchema {
		sn := sanitiseName(attr.Name)
		if attr.ResourceName != "" {
			sn = sanitiseName(attr.ResourceName)
		}
		sanitisedNames[attr.Name] = sn
		fmt.Printf("\"%s=%s\",\n", attr.Name, sn)
	}
	fmt.Println("\n\n\n")
	for k, v := range sanitisedNames {
		fmt.Printf("<Value>%s=%s</Value>\n", k, v)
	}
	fmt.Println("\n\n\n")
	count := 900
	for _, v := range sanitisedNames {
		fmt.Printf("attributeTypes: ( 1.3.6.1.4.1.36733.2.2.1.%d NAME '%s' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-ORIGIN 'OpenAM' )\n", count, v)
		count++
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		fmt.Printf(" $ %s", v)
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		fmt.Printf("\"%s\",\n", v)
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		fmt.Printf("<Value>%s</Value>\n", v)
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		noDashName := strings.ReplaceAll(v, "-", "")
		fmt.Printf(",\"%s\":{\"title\":\"%s\",\"description\":\"%s\",\"viewable\":true,\"type\":\"string\",\"searchable\":true,\"userEditable\":false,\"usageDescription\":null,\"isPersonal\":false}", noDashName, noDashName, noDashName)
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		noDashName := strings.ReplaceAll(v, "-", "")
		fmt.Printf("\"%s\":{\"type\":\"simple\",\"ldapAttribute\":\"%s\"},", noDashName, v)
	}
	fmt.Println("\n\n\n")
	for _, v := range sanitisedNames {
		noDashName := strings.ReplaceAll(v, "-", "")
		fmt.Printf("\"%s\",", noDashName)
	}
}

//"kbaInfo": {
//"description": "KBA Info",
//"isPersonal": true,
//"items": {
//"order": [
//"answer",
//"customQuestion",
//"questionId"
//],
//"properties": {
//"answer": {
//"description": "Answer",
//"type": "string"
//},
//"customQuestion": {
//"description": "Custom question",
//"type": "string"
//},
//"questionId": {
//"description": "Question ID",
//"type": "string"
//}
//},
//"required": [],
//"title": "KBA Info Items",
//"type": "object"
//},
//"type": "array",
//"usageDescription": "",
//"userEditable": true,
//"viewable": false
//},