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

import static org.forgerock.am.iot.AbstractJwtNode.JWT_VERIFIED_CLAIMS_KEY;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.Set;

import javax.inject.Inject;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.forgerock.http.Client;
import org.forgerock.http.header.AuthorizationHeader;
import org.forgerock.http.header.ContentTypeHeader;
import org.forgerock.http.header.GenericHeader;
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
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.util.i18n.PreferredLocales;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.sun.identity.authentication.callbacks.HiddenValueCallback;
import com.sun.identity.idm.AMIdentity;

import sun.security.util.Pem;

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
    protected static final String SUCCESS_OUTCOME = "success";
    protected static final String FAILURE_OUTCOME = "failure";
    private final Config config;
    private final Realm realm;
    private final CoreWrapper coreWrapper;
    private final Client httpClient;

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
     * @param coreWrapper Wrapper for abstracting core AM functionality.
     * @param httpClient The HTTP client.
     */
    @Inject
    public EstNode(@Assisted Realm realm, @Assisted Config config, CoreWrapper coreWrapper,
            Client httpClient) {
        this.realm = realm;
        this.config = config;
        this.coreWrapper = coreWrapper;
        this.httpClient = httpClient;
    }

    @Override
    public Action process(TreeContext context) {
        // Get username from transient state
        NodeState nodeState = context.getStateFor(this);
        JsonValue username = nodeState.get(USERNAME);
        if (username.isNull()) {
            logger.error("No username found.");
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        AMIdentity identity = coreWrapper.getIdentity(username.asString(), realm);
        if (identity == null) {
            logger.error("Cannot find identity.");
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        try {
            // Read attributes
            Map<String, Set<String>> attributes = identity.getAttributes();
            Set<String> keys = attributes.keySet();

            boolean certificateExists = keys.contains(config.certificateName());
            boolean rotateExists = keys.contains(config.certificateRotationName());
            boolean rotateRequired = false;
            if (certificateExists) {
                // Read rotate attribute from identity
                if (rotateExists) {
                    Set<String> rotateAttr = identity.getAttribute(config.certificateRotationName());
                    rotateRequired = Boolean.parseBoolean(rotateAttr.iterator().next());
                }

                // If rotation is not required
                if (!rotateExists || !rotateRequired) {
                    // Nothing left to do here
                    return Action.goTo(SUCCESS_OUTCOME).build();
                }
            }

            // Get callbacks
            Optional<Action> callbackAction = callbackRequired(context);
            if (callbackAction.isPresent()) {
                return callbackAction.get();
            }

            // Get CSR otherwise
            String csr = getCSR(context).orElseThrow(() -> new NodeProcessException("No CSR found."));

            // Use CSR to request new certificate from CA
            return requestCertificate(csr, identity);
        } catch (Exception e) {
            logger.error("Something went wrong", e);
            return Action.goTo(FAILURE_OUTCOME).build();
        }
    }

    /**
     * Check if a callback is already present on the request and if not, return the appropriate callback.
     *
     * @param context The tree request context.
     * @return A callback if required.
     */
    protected Optional<Action> callbackRequired(TreeContext context) {
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

    private Action requestCertificate(String csr, AMIdentity identity) throws Exception {
        String credentials = config.estUsername() + ":" + new String(config.estPassword());
        byte[] encodedCredentials = Base64.getEncoder().encode(credentials.getBytes());

        // Configure request
        Request request = new Request();
        request.setUri(config.estUrl());
        request.setMethod("POST");
        request.addHeaders(AuthorizationHeader.valueOf("Basic " + new String(encodedCredentials)),
                ContentTypeHeader.valueOf("application/pkcs10"),
                new GenericHeader("Content-Transfer-Encoding", "base64"));
        request.setEntity(csr);

        // Send request to certificate authority
        Response response = httpClient.send(request).get();
        if (!response.getStatus().isSuccessful()) {
            logger.error("Unsuccessful request to certificate authority.");
            return Action.goTo(FAILURE_OUTCOME).build();
        }

        // Extract certificate from response
        String certificateString = response.getEntity().getString().replaceAll("\n", "");
        CMSSignedData signedData = new CMSSignedData(Pem.decode(certificateString));
        X509CertificateHolder cert = signedData.getCertificates().getMatches(null).iterator().next();
        X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(cert);
        String pem = "-----BEGIN CERTIFICATE-----\n" +
                new String(Base64.getEncoder().encode(certificate.getEncoded())) +
                "\n-----END CERTIFICATE-----\n";

        // Update certificate and reset rotate for the identity
        identity.setAttributes(Collections.singletonMap(config.certificateName(), Collections.singleton(pem)));
        identity.setAttributes(
                Collections.singletonMap(config.certificateRotationName(), Collections.singleton("false"))
        );
        identity.store();

        return Action.goTo(SUCCESS_OUTCOME).build();
    }

    @Override
    public InputState[] getInputs() {
        return new InputState[] {
                new InputState(USERNAME),
                new InputState(JWT_VERIFIED_CLAIMS_KEY)
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
