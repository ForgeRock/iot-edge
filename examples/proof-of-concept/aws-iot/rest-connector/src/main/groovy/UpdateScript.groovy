/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */


import static groovyx.net.http.ContentType.JSON
import static groovyx.net.http.Method.GET
import static groovyx.net.http.Method.PUT

import org.identityconnectors.framework.common.exceptions.InvalidCredentialException
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException
import org.identityconnectors.framework.common.exceptions.UnknownUidException

import groovy.json.JsonBuilder
import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.Uid

def operation = operation as OperationType
def updateAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def name = id as String
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def uid = uid as Uid

log.info("Entering " + operation + " Script");

switch (operation) {
    case OperationType.UPDATE:
        def builder = new JsonBuilder()
        switch (objectClass) {
            case ObjectClass.ACCOUNT:
                // Since we do a PUT we need all attributes first
                connection.request(GET, JSON) { req ->
                    uri.path = '/api/users/' + uid.uidValue

                    response.success = { resp, json ->
                        assert resp.status == 200
                        log.ok 'Get was successful'
                        log.ok resp.data

                        def resultContactInformation = json.contactInformation
                        def resultDisplayName = json.displayName
                        def resultName = json.name
                        builder {
                            contactInformation {
                                telephoneNumber(updateAttributes.hasAttribute("telephoneNumber")
                                        ? updateAttributes.findString("telephoneNumber")
                                        : resultContactInformation.telephoneNumber)
                                emailAddress(updateAttributes.hasAttribute("emailAddress")
                                        ? updateAttributes.findString("emailAddress")
                                        : resultContactInformation.emailAddress)
                            }
                            displayName(updateAttributes.hasAttribute("displayName")
                                    ? updateAttributes.findString("displayName")
                                    : resultDisplayName)
                            delegate.name({
                                familyName(updateAttributes.hasAttribute("familyName")
                                        ? updateAttributes.findString("familyName")
                                        : resultName.familyName)
                                givenName(updateAttributes.hasAttribute("givenName")
                                        ? updateAttributes.findString("givenName")
                                        : resultName.givenName)
                            })
                        }
                    }

                    response.failure = { resp, json ->
                        log.error 'Get failed'
                        log.error resp.status.toString()
                        assert resp.status >= 400
                        switch (resp.status) {
                            case 401 :
                                throw new InvalidCredentialException()
                            case 403 :
                                throw new PermissionDeniedException()
                            case 404 :
                                throw new UnknownUidException("Entry not found")
                            default :
                                throw new ConnectorException("Get Failed")
                        }
                    }
                }

                return connection.request(PUT, JSON) { req ->
                    uri.path = "/api/users/${uid.uidValue}"
                    body = builder.toString()
                    headers.'If-Match' = "*"

                    response.success = { resp, json ->
                        new Uid(json._id, json._rev)
                    }
                }
            case ObjectClass.GROUP:
                // Make sure the group exists
                connection.request(GET, JSON) { req ->
                    uri.path = '/api/groups/' + uid.uidValue

                    response.failure = { resp, json ->
                        log.error 'Get failed'
                        log.error resp.status.toString()
                        assert resp.status >= 400
                        switch (resp.status) {
                            case 401:
                                throw new InvalidCredentialException()
                            case 403:
                                throw new PermissionDeniedException()
                            case 404:
                                throw new UnknownUidException("Entry not found")
                            default:
                                throw new ConnectorException("Get Failed")
                        }
                    }
                }

                if (updateAttributes.hasAttribute("members")) {
                    builder {
                        members(updateAttributes.findList("members"))
                    }
                    return connection.request(PUT, JSON) { req ->
                        uri.path = "/api/groups/${uid.uidValue}"
                        body = builder.toString()
                        headers.'If-Match' = "*"

                        response.success = { resp, json ->
                            new Uid(json._id, json._rev)
                        }
                    }
                }
                break
            default:
                throw new ConnectorException("UpdateScript can not handle object type: " + objectClass.objectClassValue)
        }
        break
    case OperationType.ADD_ATTRIBUTE_VALUES:
        throw new UnsupportedOperationException(operation.name() + " operation of type:" +
                objectClass.objectClassValue + " is not supported.")
    case OperationType.REMOVE_ATTRIBUTE_VALUES:
        throw new UnsupportedOperationException(operation.name() + " operation of type:" +
                objectClass.objectClassValue + " is not supported.")
    default:
        throw new ConnectorException("UpdateScript can not handle operation:" + operation.name())
}
return uid