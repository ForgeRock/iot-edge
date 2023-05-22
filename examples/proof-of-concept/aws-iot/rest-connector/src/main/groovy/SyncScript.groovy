/*
 * Copyright 2014-2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */


import groovy.json.JsonSlurper
import org.apache.http.client.methods.HttpGet
import org.apache.http.client.utils.URIBuilder
import org.apache.http.impl.client.BasicResponseHandler
import org.apache.http.util.EntityUtils

import java.net.http.HttpResponse
import java.text.SimpleDateFormat

import static groovyx.net.http.Method.GET

import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.SyncToken

def things = new ObjectClass("THINGS")
def simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS`Z`")

def operation = operation as OperationType
//def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def log = log as Log
def objectClass = objectClass as ObjectClass

log.info("Entering " + operation + " Script")

if (things != objectClass) {
    throw new IllegalArgumentException(String.format("Operation requires ObjectClass %s, received %s",
            things.getDisplayNameKey(), objectClass));
}

if (OperationType.GET_LATEST_SYNC_TOKEN == operation) {

    return new SyncToken(simpleDateFormat.format(new Date()))

} else if (OperationType.SYNC == operation) {
    def token = token as Object
    log.info("Entering SYNC")

    // See: https://docs.aws.amazon.com/iot/latest/apireference/API_ListThings.html
    def httpGet = new HttpGet("/things")
    def uri = new URIBuilder(httpGet.getURI())
            .addParameter("maxResults", "100")
            .addParameter("param2", "value2")
            .build()
    httpGet.setURI(uri)

    def httpResponse = httpClient.execute(httpGet)
    def responseString = EntityUtils.toString(httpResponse.getEntity())
    def jsonSlurper = new JsonSlurper()
    def thingList = jsonSlurper.parseText(responseString)

//    return connection.request(GET, { req ->
//        uri.path = "/things"
//        uri.query = [
//            maxResults: "100"
//        ]
//
//        response.success = { resp, json ->
//            def lastToken = token
//            json.result.each() { changeLogEntry ->
//                lastToken = changeLogEntry._id
//
//                String resourceId = changeLogEntry.targetDN
//                resourceId = resourceId.substring(4, resourceId.indexOf(','))
//
//                handler({
//                    syncToken lastToken
//                    if ("add".equals(changeLogEntry.changeType)) {
//                        CREATE()
//                    } else if ("modify".equals(changeLogEntry.changeType)) {
//                        UPDATE()
//                    } else if ("delete".equals(changeLogEntry.changeType)) {
//                        DELETE()
//                        object {
//                            uid resourceId
//                            id resourceId
//                            delegate.objectClass(objectClass)
//                        }
//                        return
//                    } else {
//                        CREATE_OR_UPDATE()
//                    }
//
//                    connection.request(GET) { getReq ->
//                        uri.path = '/api/users/' + resourceId
//
//                        response.success = { getResp, value ->
//                            object {
//                                uid value._id
//                                id value._id
//                                attribute 'telephoneNumber', value?.contactInformation?.telephoneNumber
//                                attribute 'emailAddress', value?.contactInformation?.emailAddress
//                                attribute 'familyName', value?.name?.familyName
//                                attribute 'givenName', value?.name?.givenName
//                                attribute 'displayName', value?.displayName
//                                attribute('groups', *(value?.groups))
//                                attribute 'created', value?._meta?.created
//                                attribute 'lastModified', value?._meta?.lastModified
//                            }
//
//                        }
//
//                        response."404" = { getResp, error ->
//                            DELETE()
//                            object {
//                                uid resourceId
//                                id resourceId
//                                delegate.objectClass(objectClass)
//                            }
//                        }
//
//                        response.failure = { getResp, error ->
//                            throw new ConnectException(error.message)
//                        }
//                    }
//
//                })
//            }
//            return new SyncToken(lastToken)
//        }
//
//        response.failure = { resp, json ->
//            throw new ConnectException(json.message)
//        }


} else { // action not implemented
    log.error("Sync script: action '" + operation + "' is not implemented in this script");
}
