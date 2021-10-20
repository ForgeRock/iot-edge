package com.example.forgetv;

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


public class AuthThingSigner {
    String thingID;
    String audience;
    String kid;

    public AuthThingSigner(String kid, String thingID, String audience) {
        this.kid = kid;
        this.thingID = thingID;

        if(audience.equals("root")) {
            audience = "/";
        }
        this.audience = audience;
    }

    public String sign(String nonce) throws ParseException, JOSEException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException {
        // load private key from keystore
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey key = (PrivateKey) keyStore.getKey("forgerock", null);
        ECDSASigner signer = new ECDSASigner(key, Curve.P_256);

        // write claims
        long unixTime = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", thingID);
        claims.put("iat", unixTime);
        claims.put("exp", unixTime + 86400);
        claims.put("aud", audience);
        claims.put("nonce", nonce);
        Map<String, String> cnf = new HashMap<>();
        cnf.put("kid", kid);
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
