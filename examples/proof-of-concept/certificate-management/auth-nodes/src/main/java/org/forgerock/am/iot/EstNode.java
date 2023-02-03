/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
 */

package org.forgerock.am.iot;

import static java.util.Collections.emptySet;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import javax.inject.Inject;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.forgerock.http.Client;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.header.MalformedHeaderException;
import org.forgerock.http.protocol.Entity;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.InputState;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.StaticOutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;

/**
 * This node handles the issue of certificates for things using the Enrollment over Secure Transport (EST) protocol.
 * It is responsible for verifying that the thing's identity exists, and determining whether the thing requires a
 * new certificate. If there is no existing certificate or the certificate must be rotated, then the node will request
 * a Certificate Signing Request (CSR) via callback. This CSR will be used to request a new certificate using EST, and
 * the new certificate will be stored in the thing's identity.
 */
@Node.Metadata(
        outcomeProvider = EstNode.CertificateOutcomeProvider.class,
        configClass = EstNode.Config.class,
        tags = {"iot", "things"})
public class EstNode implements Node {
    private static final Logger logger = LoggerFactory.getLogger(EstNode.class);
    private static final String BUNDLE = EstNode.class.getName();
    private static final String CSR_CALLBACK = "csr";
    private static final String SUCCESS_OUTCOME = "success";
    private static final String FAILURE_OUTCOME = "failure";
    private final Config config;
    private final Realm realm;
    private final Client httpClient;
    private AMIdentity identity;

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The URL of the EST server (Certificate Authority).
         *
         * @return The URL of the EST server.
         */
        @Attribute(order = 100)
        String estUrl();

        /**
         * The user ID of the EST client.
         *
         * @return The user ID of the EST client.
         */
        @Attribute(order = 200)
        String estUsername();

        /**
         * The password of the EST client.
         *
         * @return The password of the EST client.
         */
        @Attribute(order = 300)
        @Password
        char[] estPassword();

        /**
         * The attribute name used to store the certificate.
         *
         * @return The attribute name used to store the certificate.
         */
        @Attribute(order = 400)
        String certificateName();

        /**
         * The attribute name used to store whether certificate rotation is required.
         *
         * @return The attribute name used to store whether certificate rotation is required.
         */
        @Attribute(order = 500)
        String certificateRotationName();
    }

    /**
     * Create an instance of the {@link EstNode}.
     *
     * @param realm The realm in which to create the node.
     * @param config The node configuration.
     * @param httpClient The HTTP client.
     */
    @Inject
    public EstNode(@Assisted Realm realm, @Assisted Config config, Client httpClient) {
        this.realm = realm;
        this.config = config;
        this.httpClient = httpClient;
    }

    @Override
    public Action process(TreeContext context) {
        // Get identity from AM
        identity = getIdentity(context);
        if (identity == null) {
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        // Get attributes from identity
        Set<String> keys = readAttributes();
        if (keys.equals(emptySet())) {
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        // Check if certificate needs to be rotated
        if (!isRotateRequired(keys)) {
            // Nothing else to do here
            return Action.goTo(SUCCESS_OUTCOME).build();
        }

        // Get callbacks
        Optional<Action> callbackAction = callbackRequired(context);
        if (callbackAction.isPresent()) {
            return callbackAction.get();
        }

        // Get CSR otherwise
        String csr;
        try {
            csr = getCSR(context).orElseThrow(() -> new NodeProcessException("No CSR found."));
        } catch (NodeProcessException e) {
            logger.error("Failed to get CSR: {}", e.getMessage());
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        // Use CSR to request new certificate from CA
        if (!requestCertificate(csr)) {
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        return Action.goTo(SUCCESS_OUTCOME).build();
    }

    private Optional<Action> callbackRequired(TreeContext context) {
        if (!context.getCallbacks(HiddenValueCallback.class).isEmpty()) {
            return Optional.empty();
        }

        List<HiddenValueCallback> callbacks = new ArrayList<>();
        callbacks.add(new HiddenValueCallback(CSR_CALLBACK));

        return Optional.of(Action.send(callbacks).build());
    }

    private Optional<String> getCSR(TreeContext context) {
        for (HiddenValueCallback callback : context.getCallbacks(HiddenValueCallback.class)) {
            if (!callback.getId().equalsIgnoreCase(CSR_CALLBACK)) {
                continue;
            }

            return Optional.ofNullable(callback.getValue());
        }

        return Optional.empty();
    }

    private AMIdentity getIdentity(TreeContext context) {
        // Get username from transient state
        NodeState nodeState = context.getStateFor(this);
        JsonValue username = nodeState.get(USERNAME);

        if (username == null || username.isNull()) {
            logger.error("Failed to read username from node state.");
            return null;
        }

        String usernameString = username.asString();
        AMIdentity identity = IdUtils.getIdentity(usernameString, realm);
        if (identity == null) {
            logger.error("Failed to find identity with username '{}'.", usernameString);
            return null;
        }

        return identity;
    }

    private String getName() {
        return identity.getName();
    }

    private Set<String> readAttributes() {
        Map<String, Set<String>> attributes;
        try {
            attributes = identity.getAttributes();
            return attributes.keySet();
        } catch (IdRepoException | SSOException e) {
            logger.error("Failed to read attributes for '{}'.", getName());
            return emptySet();
        }
    }

    private boolean isRotateRequired(Set<String> keys) {
        boolean certificateExists = keys.contains(config.certificateName());
        boolean rotateExists = keys.contains(config.certificateRotationName());
        boolean rotateRequired = false;

        // Read rotate attribute from identity if certificate exists
        if (certificateExists) {
            if (rotateExists) {
                Set<String> rotateAttr;
                try {
                    rotateAttr = identity.getAttribute(config.certificateRotationName());
                } catch (IdRepoException | SSOException e) {
                    logger.error("Failed to read rotate attribute '{}' for identity '{}'",
                            config.certificateRotationName(), getName());
                    return false;
                }
                if (rotateAttr != null) {
                    rotateRequired = Boolean.parseBoolean(rotateAttr.iterator().next());
                }
            }
        }

        return !certificateExists || (rotateExists && rotateRequired);
    }

    private boolean requestCertificate(String csr) {
        Request request = new Request();
        if (!configureRequest(request, csr)) {
            return false;
        }

        return sendRequest(request);
    }

    private boolean configureRequest(Request request, String csr) {
        String credentials = config.estUsername() + ":" + new String(config.estPassword());
        byte[] encodedCredentials = Base64.getEncoder().encode(credentials.getBytes());

        try {
            request.setUri(config.estUrl());
        } catch (URISyntaxException e) {
            logger.error("Failed to set request URI: {}", e.getMessage());
            return false;
        }

        try {
            request.addHeaders(AuthorizationHeader.valueOf("Basic " + new String(encodedCredentials)),
                    ContentTypeHeader.valueOf("application/pkcs10"),
                    new GenericHeader("Content-Transfer-Encoding", "base64"));
        } catch (MalformedHeaderException e) {
            logger.error("Failed to set request headers: {}", e.getMessage());
            return false;
        }

        request.setMethod("POST");
        request.setEntity(csr);

        return true;
    }

    private boolean sendRequest(Request request) {
        Response response;
        try {
            response = httpClient.send(request).get();
        } catch (ExecutionException | InterruptedException e) {
            logger.error("Failed to send request to certificate authority: {}", e.getMessage());
            return false;
        }

        if (!response.getStatus().isSuccessful()) {
            String error = response.getStatus().toString();

            // Get more specific reason from response entity if exists
            if (!response.getEntity().isRawContentEmpty()) {
                try {
                    error = response.getEntity().getString();
                } catch (IOException e) {
                    logger.error("Failed to read response entity: {}", e.getMessage());
                }
            }

            logger.error("Failed to receive successful response from certificate authority: {}", error);
            return false;
        }

        return extractCertificate(response.getEntity());
    }

    private boolean extractCertificate(Entity entity) {
        String entityString = getEntityString(entity);
        if (entityString == null) {
            return false;
        }

        String certificateString = removeNewLines(entityString);
        X509CertificateHolder cert = loadCertificate(certificateString);
        if (cert == null) {
            return false;
        }

        X509Certificate certificate = convertCertificate(cert);
        if (certificate == null) {
            return false;
        }

        String pem = encodeCertificate(certificate);
        if (pem == null) {
            return false;
        }

        return updateIdentity(pem);
    }

    private String getEntityString(Entity entity) {
        String entityString;
        try {
            entityString = entity.getString();
        } catch (IOException e) {
            logger.error("Failed to read response entity as string: {}", e.getMessage());
            return null;
        }

        return entityString;
    }

    private String removeNewLines(String stringToFormat) {
        return stringToFormat.replaceAll("\n", "");
    }

    private X509CertificateHolder loadCertificate(String certificateString) {
        CMSSignedData signedData;
        byte[] certificateBytes = certificateString.replaceAll("\\s+", "")
                .getBytes(StandardCharsets.ISO_8859_1);

        try {
            signedData = new CMSSignedData(Base64.getDecoder().decode(certificateBytes));
        } catch (CMSException e) {
            logger.error("Failed to find certificate for the signer: " + e.getMessage());
            return null;
        }

        return signedData.getCertificates().getMatches(null).iterator().next();
    }

    private X509Certificate convertCertificate(X509CertificateHolder cert) {
        X509Certificate certificate;
        try {
            certificate = new JcaX509CertificateConverter().getCertificate(cert);
        } catch (CertificateException e) {
            logger.error("Failed to convert certificate: {}", e.getMessage());
            return null;
        }

        return certificate;
    }

    private String encodeCertificate(X509Certificate certificate) {
        String pem;
        try {
            pem = "-----BEGIN CERTIFICATE-----\n" +
                    new String(Base64.getEncoder().encode(certificate.getEncoded())) +
                    "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            logger.error("Failed to encode certificate: {}", e.getMessage());
            return null;
        }

        return pem;
    }

    private boolean updateIdentity(String pem) {
        try {
            identity.setAttributes(Collections.singletonMap(config.certificateName(), Collections.singleton(pem)));
        } catch (IdRepoException | SSOException e) {
            logger.error("Failed to set '{}' attribute for identity '{}': {}", config.certificateName(), getName(),
                    e.getMessage());
            return false;
        }

        try {
            identity.setAttributes(
                    Collections.singletonMap(config.certificateRotationName(), Collections.singleton("false"))
            );
        } catch (IdRepoException | SSOException e) {
            logger.error("Failed to set '{}' attribute for identity '{}': {}", config.certificateRotationName(),
                    getName(), e.getMessage());
            return false;
        }

        try {
            identity.store();
        } catch (IdRepoException | SSOException e) {
            logger.error("Failed to update identity '{}': {}", getName(), e.getMessage());
            return false;
        }

        return true;
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[] {
                new InputState(USERNAME),
        };
    }

    /**
     * Defines the possible outcomes from this node.
     */
    public static class CertificateOutcomeProvider implements StaticOutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales) {
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());

            return List.of(new Outcome(SUCCESS_OUTCOME, bundle.getString(SUCCESS_OUTCOME)),
                    new Outcome(FAILURE_OUTCOME, bundle.getString(FAILURE_OUTCOME)));
        }
    }
}
