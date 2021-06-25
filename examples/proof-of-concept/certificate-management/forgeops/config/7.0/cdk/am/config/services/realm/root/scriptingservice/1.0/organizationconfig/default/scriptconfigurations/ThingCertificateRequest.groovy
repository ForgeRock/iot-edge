/*
 * Copyright 2021 ForgeRock AS
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


import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.forgerock.http.header.AuthorizationHeader
import org.forgerock.http.header.ContentTypeHeader
import org.forgerock.http.header.GenericHeader
import org.forgerock.http.protocol.Request
import sun.security.util.Pem
import org.forgerock.openam.auth.node.api.NodeState
import java.security.cert.X509Certificate

outcome = "Success"
NodeState state = nodeState

if (!state.isDefined("objectAttributes")) {
    logger.message("No object attributes found in shared state.")
    outcome = "Failure"
    return
}
def attrs = state.get("objectAttributes")
if (!attrs.isDefined("thingProperties")) {
    logger.message("No properties included in the device authentication request.")
    outcome = "Failure"
    return
}
def thingProps = new String(Base64.getDecoder().decode(attrs.get("thingProperties").asString()))
attrs.put("thingProperties", thingProps)
def jsonSlurper = new JsonSlurper()
def jsonProps = jsonSlurper.parseText(thingProps)
if (!jsonProps.csr) {
    logger.message("No Certificate Signing Request included in the device authentication request.")
    outcome = "Failure"
    return
}
def encodedCredentials = Base64.getEncoder().encode("estuser:estpwd".getBytes())
def request = new Request()
request.setUri("https://testrfc7030.com:8443/.well-known/est/simpleenroll")
request.setMethod("POST")
request.addHeaders(
        AuthorizationHeader.valueOf("Basic " + new String(encodedCredentials)),
        ContentTypeHeader.valueOf("application/pkcs10"),
        new GenericHeader("Content-Transfer-Encoding", "base64"))
request.setEntity(jsonProps.csr)
def response = httpClient.send(request).get()
String certString = response.getEntity().getString().replaceAll("\n", "")
logger.message("Certificate: " + certString)

CMSSignedData signedData = new CMSSignedData(Pem.decode(certString))
X509CertificateHolder cert = signedData.getCertificates().getMatches(null).iterator().next()
X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(cert)
def pem = "-----BEGIN CERTIFICATE-----\n" +
        new String(Base64.getEncoder().encode(certificate.getEncoded())) +
        "\n-----END CERTIFICATE-----"
def thingConfig = JsonOutput.toJson([cert: pem, rotate: false])
attrs.add("thingConfig", thingConfig)
sharedState.put("objectAttributes", attrs)
