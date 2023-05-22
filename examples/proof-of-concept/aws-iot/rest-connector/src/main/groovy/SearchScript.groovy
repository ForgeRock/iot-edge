/*
 * Copyright 2014-2018 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */


import static groovyx.net.http.Method.GET

import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.forgerock.openicf.connectors.scriptedrest.SimpleCRESTFilterVisitor
import org.forgerock.openicf.connectors.scriptedrest.VisitorParameter
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributeUtil
import org.identityconnectors.framework.common.objects.Name
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.SearchResult
import org.identityconnectors.framework.common.objects.Uid
import org.identityconnectors.framework.common.objects.filter.Filter

def operation = operation as OperationType
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def filter = filter as Filter
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def resultHandler = handler

log.info("Entering " + operation + " Script")

def query = [:]
def queryFilter = 'true'
if (filter != null) {
    queryFilter = filter.accept(SimpleCRESTFilterVisitor.INSTANCE, [
            translateName: { String name ->
                if (AttributeUtil.namesEqual(name, Uid.NAME)) {
                    return "_id"
                } else if (AttributeUtil.namesEqual(name, Name.NAME)) {
                    return "_id"
                } else if (AttributeUtil.namesEqual(name, "telephoneNumber")) {
                    return "contactInformation/telephoneNumber"
                } else if (AttributeUtil.namesEqual(name, "emailAddress")) {
                    return "contactInformation/emailAddress"
                } else if (AttributeUtil.namesEqual(name, "familyName")) {
                    return "name/familyName"
                } else if (AttributeUtil.namesEqual(name, "givenName")) {
                    return "name/givenName"
                } else if (AttributeUtil.namesEqual(name, "displayName")) {
                    return "displayName"
                } else if (AttributeUtil.namesEqual(name, "members")) {
                    return "members"
                } else {
                    throw new IllegalArgumentException("Unknown field name: OpenIDM Scripted REST to DJ Sample");
                }
            },
            convertValue : { Attribute value ->
                if (AttributeUtil.namesEqual(value.name, "members")) {
                    return value.value
                } else {
                    return AttributeUtil.getStringValue(value)
                }
            }] as VisitorParameter).toString();
}

query['_queryFilter'] = queryFilter

if (null != options.pageSize) {
    query['_pageSize'] = options.pageSize
    if (null != options.pagedResultsCookie) {
        query['_pagedResultsCookie'] = options.pagedResultsCookie
    }
    if (null != options.pagedResultsOffset) {
        query['_pagedResultsOffset'] = options.pagedResultsOffset
    }
}

switch (objectClass) {
    case ObjectClass.ACCOUNT:
        def searchResult = connection.request(GET) { req ->
            uri.path = '/api/users'
            uri.query = query

            response.success = { resp, json ->
                json.result.each() { value ->
                    resultHandler {
                        uid value._id
                        id value._id
                        attribute 'telephoneNumber', value?.contactInformation?.telephoneNumber
                        attribute 'emailAddress', value?.contactInformation?.emailAddress
                        attribute 'familyName', value?.name?.familyName
                        attribute 'givenName', value?.name?.givenName
                        attribute 'displayName', value?.displayName
                        attribute('groups', *(value?.groups))
                        attribute 'created', value?._meta?.created
                        attribute 'lastModified', value?._meta?.lastModified
                    }
                }
                json
            }
        }

        return new SearchResult(searchResult.pagedResultsCookie, searchResult.remainingPagedResults)

    case ObjectClass.GROUP:
        def searchResult = connection.request(GET) { req ->
            uri.path = '/api/groups'
            uri.query = query

            response.success = { resp, json ->
                json.result.each() { value ->
                    resultHandler {
                        uid value._id
                        id value._id
                        attribute('members', *(value?.members))
                        attribute 'displayName', value?.displayName
                        attribute 'created', value?._meta?.created
                        attribute 'lastModified', value?._meta?.lastModified
                    }
                }
                json
            }
        }

        return new SearchResult(searchResult.pagedResultsCookie, searchResult.remainingPagedResults)
}
