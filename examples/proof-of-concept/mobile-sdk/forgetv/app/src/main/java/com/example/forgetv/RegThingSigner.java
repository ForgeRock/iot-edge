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

package com.example.forgetv;

import android.util.Base64;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class RegThingSigner {
    String thingID;
    String audience;
    String kid;

    public RegThingSigner(String kid, String thingID, String audience) {
        this.kid = kid;
        this.thingID = thingID;

        if(audience.equals("root")) {
            audience = "/";
        }
        this.audience = audience;
    }

    public String sign(String nonce) throws JOSEException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, JSONException {
        // load private key from keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey key = (PrivateKey) keyStore.getKey("forgerock", null);
        PublicKey publicKey = keyStore.getCertificate("forgerock").getPublicKey();
        Certificate certificate = keyStore.getCertificate("forgerockCert");
        ECDSASigner signer = new ECDSASigner(key, Curve.P_256);

        // write claims
        long unixTime = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", thingID);
        claims.put("iat", unixTime);
        claims.put("exp", unixTime + 86400);
        claims.put("aud", "/");
        claims.put("thingType", "device");
        claims.put("nonce", nonce);
        Map<String, Object> cnf = new HashMap<>();
        ECKey esKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                .keyID(kid)
                .keyUse(KeyUse.SIGNATURE)
                .build();

        // get public key as JWK
        // convert from JSONObject since this breaks in JWSObject
        JSONObject jwk = new JSONObject(esKey.toJSONObject());
        Iterator<String> keys = jwk.keys();
        Map<String, Object> jwkMap = new HashMap<>();
        while(keys.hasNext()) {
            String lkey = keys.next();
            jwkMap.put(lkey, jwk.get(lkey));
        }

        // add the certificate to the JWK
        jwkMap.put("x5c", new String[]{Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP)});
        cnf.put("jwk", jwkMap);
        claims.put("cnf", cnf);

        // create JWT
        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build(),
                new Payload(claims));

        try {
            jwsObject.sign(signer);
            return jwsObject.serialize();
        } catch (JOSEException joseException) {
            joseException.printStackTrace();
        }
        return "";

    }
}
