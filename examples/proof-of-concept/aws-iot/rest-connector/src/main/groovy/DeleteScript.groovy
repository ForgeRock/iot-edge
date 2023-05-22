/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */


import static groovyx.net.http.Method.DELETE

import org.identityconnectors.framework.common.exceptions.ConnectorException
import org.identityconnectors.framework.common.exceptions.InvalidCredentialException
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException
import org.identityconnectors.framework.common.exceptions.UnknownUidException

import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.Uid

def operation = operation as OperationType
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def uid = uid as Uid

log.info("Entering " + operation + " Script")

def path
switch (objectClass) {
    case ObjectClass.ACCOUNT:
        path = '/api/users/' + uid.uidValue
        break
    case ObjectClass.GROUP:
        path = '/api/groups/' + uid.uidValue
}

connection.request(DELETE) { req ->
    uri.path = path

    response.success = { resp, json ->
        assert resp.status == 200
        log.ok 'Delete was successful'
        log.ok resp.status.toString()
    }

    response.failure = { resp, json ->
        log.error 'Delete failed'
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
                throw new ConnectorException("Delete Failed")
        }
    }
}
