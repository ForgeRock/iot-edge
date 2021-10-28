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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


public class RegThingSigner extends AbstractJWTSigner {
    public RegThingSigner(String kid, String thingID, String audience) {
        super(kid, thingID, audience);
    }

    @Override
    Map<String, Object> extraClaims() {
        Map<String, Object> claims = new HashMap<>();

        // add the thing type
        claims.put("thingType", "device");

        // add the certificate in the cnf
        Map<String, Object> cnf = new HashMap<>();
        try {
            KeyStore keyStore = KeyStore.getInstance(PROVIDER);
            keyStore.load(null);
            Certificate certificate = keyStore.getCertificate(CERT_ALIAS);
            PublicKey publicKey = certificate.getPublicKey();
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
                String key = keys.next();
                jwkMap.put(key, jwk.get(key));
            }

            // add the certificate to the JWK
            jwkMap.put("x5c", new String[]{Base64.encodeToString(certificate.getEncoded(), Base64.NO_WRAP)});
            cnf.put("jwk", jwkMap);
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException | JSONException e) {
            e.printStackTrace();
        }
        claims.put("cnf", cnf);

        return claims;
    }
}
