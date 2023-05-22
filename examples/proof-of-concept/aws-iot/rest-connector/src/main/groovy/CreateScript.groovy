/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

import static groovyx.net.http.ContentType.JSON

import groovy.json.JsonBuilder
import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions

def operation = operation as OperationType
def createAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def name = id as String
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions

log.info("Entering " + operation + " Script");

switch (objectClass) {
    case ObjectClass.ACCOUNT:
        def builder = new JsonBuilder()
        builder {
            '_id' name
            contactInformation {
                telephoneNumber(createAttributes.hasAttribute("telephoneNumber") ? createAttributes.findString("telephoneNumber") : "")
                emailAddress(createAttributes.hasAttribute("emailAddress") ? createAttributes.findString("emailAddress") : "")
            }
            delegate.name({
                familyName(createAttributes.hasAttribute("familyName") ? createAttributes.findString("familyName") : "")
                givenName(createAttributes.hasAttribute("givenName") ? createAttributes.findString("givenName") : "")
            })
            displayName(createAttributes.hasAttribute("displayName") ? createAttributes.findString("displayName") : "")
        }

        if (createAttributes.hasAttribute("password")) {
            builder.content["password"] = createAttributes.findString("password")
        }

        connection.put(
                path: '/api/users/' + name,
                headers: ['If-None-Match': '*'],
                contentType: JSON,
                requestContentType: JSON,
                body: builder.toString());
        break

    case ObjectClass.GROUP:
        def builder = new JsonBuilder()
        builder {
            '_id' name
            members(createAttributes.hasAttribute("members") ? createAttributes.findList("members") : [])
        }
        connection.put(
                path: '/api/groups/' + name,
                headers: ['If-None-Match': '*'],
                body: builder.toString());

}
return name
