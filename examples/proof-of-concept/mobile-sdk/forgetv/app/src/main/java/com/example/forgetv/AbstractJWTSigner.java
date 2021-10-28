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

import android.os.Build;

import androidx.annotation.RequiresApi;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;


abstract class AbstractJWTSigner {
    public static final String PROVIDER = "AndroidKeyStore";
    public static final String KEY_ALIAS = "forgerock";
    public static final String CERT_ALIAS = "forgerockCert";

    String thingID;
    String audience;
    String kid;

    public AbstractJWTSigner(String kid, String thingID, String audience) {
        this.kid = kid;
        this.thingID = thingID;

        if(audience.equals("root")) {
            audience = "/";
        }
        this.audience = audience;
    }

    @RequiresApi(api = Build.VERSION_CODES.N)
    public String sign(String nonce) throws ParseException, JOSEException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        // load private key from keystore
        KeyStore keyStore = KeyStore.getInstance(PROVIDER);
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        ECDSASigner signer = new ECDSASigner(privateKey, Curve.P_256);

        // store claims in Map since JSONObject breaks in JWSObject
        long unixTime = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", thingID);
        claims.put("iat", unixTime);
        claims.put("exp", unixTime + 86400);
        claims.put("aud", audience);
        claims.put("nonce", nonce);
        Map<String, Object> extras = extraClaims();
        if (extras!= null) {
            extras.forEach(claims::put);
        }

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

    abstract Map<String, Object> extraClaims();
}
