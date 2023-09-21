/*
 * Copyright 2023 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

import com.fasterxml.jackson.databind.ObjectMapper
import groovyx.net.http.RESTClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.*

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.text.SimpleDateFormat

import static groovyx.net.http.ContentType.JSON
import static groovyx.net.http.Method.GET

def operation = operation as OperationType
def connection = customizedConnection as RESTClient
def log = log as Log
def objectClass = objectClass as ObjectClass

log.info("Entering " + operation + " Script")

// Adapted from AWS SDK
class ThingAttribute {
    String thingName
    Map<String, String> attributes

    ThingAttribute(String thingName, Map<String, String> attributes) {
        this.thingName = thingName
        this.attributes = attributes
    }

    String thingName() { this.thingName }

    Map<String, String> attributes() { this.attributes }

    Boolean hasAttributes() { this.attributes() != null }
}

// AWS credentials and configuration
ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
AWS_REGION = 'us-east-1'

THINGS = new ObjectClass("__THING__")
AWS_IOT_URL = 'iot.' + AWS_REGION + '.amazonaws.com'
AWS_IOT_FULL_URL = 'https://' + AWS_IOT_URL
AWS_IOT_ENDPOINT = '/things'

if (THINGS != objectClass) {
    throw new IllegalArgumentException(String.format("Operation requires ObjectClass %s, received %s",
            THINGS.getDisplayNameKey(), objectClass))
}

private ThingAttribute buildAttribute(Object thing) {
    def thingName = thing.thingName as String
    def attributes = thing.attributes as Map<String, String>

    return new ThingAttribute(thingName, attributes)
}

private ConnectorObject buildThing(ThingAttribute thingAttribute) {
    def builder = new ConnectorObjectBuilder()
    builder.setObjectClass(THINGS as ObjectClass)
    builder.setUid(thingAttribute.thingName())
    builder.setName(thingAttribute.thingName())
    builder.addAttribute(AttributeBuilder.build('thingType', 'DEVICE'))

    // Convert attributes map to JSON string format
    if (thingAttribute.hasAttributes()) {
        def objectMapper = new ObjectMapper()
        def thingConfig = objectMapper.writeValueAsString(thingAttribute.attributes())
        builder.addAttribute(AttributeBuilder.build('thingConfig', thingConfig))
    }

    return builder.build()
}

private byte[] getSigningKey(String key, String date, String region, String service) throws NoSuchAlgorithmException, InvalidKeyException {
    def kSecret = ("AWS4" + key).getBytes(StandardCharsets.UTF_8)
    def kDate = hmacSHA256(kSecret, date)
    def kRegion = hmacSHA256(kDate, region)
    def kService = hmacSHA256(kRegion, service)

    return hmacSHA256(kService,"aws4_request")
}

private String getCanonicalRequest(String method, String path, String query, String time, String payload) throws NoSuchAlgorithmException {
    /*
        GET
        /things
        {query parameters}
        host:iot.{region}.amazonaws.com
        x-amz-date:yyyyMMdd'T'HHmmss'Z'

        host;x-amz-date
        {hashed payload}
     */
    def host = "host:$AWS_IOT_URL"
    def date = "x-amz-date:$time"
    def canonicalHeaders = host + "\n" + date
    def signedHeaders = 'host;x-amz-date'
    def hashedPayload = bytesToHex(sha256(payload))

    return method + "\n" +
            path + "\n" +
            query + "\n" +
            canonicalHeaders + "\n\n" +
            signedHeaders + "\n" +
            hashedPayload
}

private String createSigningString(String time, String date, String hashedCanonicalRequest) {
    /*
        AWS4-HMAC-SHA256
        yyyyMMdd'T'HHmmss'Z'
        yyyyMMdd/{region}/iot/aws4_request
        {hashed canonical request}
     */
    def algorithm = 'AWS4-HMAC-SHA256'
    def credentialScope = "$date/$AWS_REGION/iot/aws4_request"

    return algorithm + "\n" +
            time + "\n" +
            credentialScope + "\n" +
            hashedCanonicalRequest
}

/*
    Steps to sign an AWS API request:
    1. Create canonical request
    2. Create hash of canonical request
    3. Create string to sign
    4. Calculate the signature
 */
private String calculateSignature(String time, String date, String query) throws NoSuchAlgorithmException, InvalidKeyException {
    // Create canonical request
    def canonicalRequest = getCanonicalRequest("GET", AWS_IOT_ENDPOINT.toString(), query, time, "")

    // Create hash of canonical request
    def hashedCanonincalRequest = sha256(canonicalRequest)
    def hexHashedCanonicalRequest = bytesToHex(hashedCanonincalRequest)

    // Create string to sign
    def stringToSign = createSigningString(time, date, hexHashedCanonicalRequest)

    // Calculate the signature
    def signingKey = getSigningKey(SECRET_KEY as String, date, AWS_REGION as String, 'iot')
    def hmacSignature = hmacSHA256(signingKey, stringToSign)

    return bytesToHex(hmacSignature)
}

private byte[] sha256(String payload) throws NoSuchAlgorithmException {
    def digest = MessageDigest.getInstance("SHA-256")

    return digest.digest(payload.getBytes(StandardCharsets.UTF_8))
}

private byte[] hmacSHA256(byte[] key, String data) throws NoSuchAlgorithmException, InvalidKeyException {
    def algorithm = 'HmacSHA256'
    def secretKeySpec = new SecretKeySpec(key, algorithm)
    def mac = Mac.getInstance(algorithm)
    mac.init(secretKeySpec)

    return mac.doFinal(data.getBytes(StandardCharsets.UTF_8))
}

private String bytesToHex(byte[] bytes) {
    def sb = new StringBuilder(bytes.length * 2)
    for(byte b: bytes) {
        sb.append(String.format("%02x", b))
    }

    return sb.toString()
}

private String getAmzDateString(Date currentDateTime) {
    def amzDateFormat = new SimpleDateFormat('yyyyMMdd')

    return amzDateFormat.format(currentDateTime)
}

private String getAmzDateTimeString(Date currentDateTime) {
    def amzDateTimeFormat = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'")
    amzDateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"))

    return amzDateTimeFormat.format(currentDateTime)
}

private GString getAuthorizationHeader(String amzCurrentDateTime, String amzCurrentDate, String query) {
    def signature = calculateSignature(amzCurrentDateTime, amzCurrentDate, query)
    def credential = "$ACCESS_KEY/$amzCurrentDate/$AWS_REGION/iot/aws4_request,SignedHeaders=host;x-amz-date,Signature=$signature"

    return "AWS4-HMAC-SHA256 Credential=$credential"
}

private LinkedHashMap<String, String> getAwsHeaders(String amzCurrentDateTime, GString authHeader) {
    return ['X-Amz-Date': amzCurrentDateTime, 'Authorization': authHeader]
}

private SyncToken getLatestSyncToken(Object token) {
    return new SyncToken(token)
}

private SyncToken getNewSyncToken() {
    def syncTokenFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS`Z`")

    return new SyncToken(syncTokenFormat.format(new Date()))
}

if (OperationType.GET_LATEST_SYNC_TOKEN == operation) {
    if (binding.hasVariable('token')) {
        return getLatestSyncToken(token)
    }
    return getNewSyncToken()
} else if (OperationType.SYNC == operation) {
    return connection.request(AWS_IOT_FULL_URL, GET, JSON) { req ->
        uri.path = AWS_IOT_ENDPOINT
        headers.clear()

        // Get full timestamp and date in correct format for AWS signed request
        def currentDateTime = new Date()
        def amzCurrentDate = getAmzDateString(currentDateTime)
        def amzCurrentDateTime = getAmzDateTimeString(currentDateTime)

        // Calculate and set the Authorization header
        def authHeader = getAuthorizationHeader(amzCurrentDateTime, amzCurrentDate, "")
        def customHeaders = getAwsHeaders(amzCurrentDateTime, authHeader)
        setHeaders(customHeaders)

        response.success = { resp, json ->
            log.info("Request was successful")

            def syncToken = getNewSyncToken()
            json.things.each() { thing ->
                def thingAttribute = buildAttribute(thing)
                def device = buildThing(thingAttribute)

                def deltaBuilder = new SyncDeltaBuilder()
                deltaBuilder.setObject(device)
                deltaBuilder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE)
                deltaBuilder.setToken(syncToken)

                handler deltaBuilder.build()
            }

            return syncToken
        }

        response.failure = { resp, json ->
            log.error("Request failed with response code: " + resp.status.toString())
        }
    }
} else { // action not implemented
    log.error("Sync script: action '" + operation + "' is not implemented in this script")
}
