package com.example.forgetv;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;

import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;


public class AuthThingSigner {
    String privateJWK;
    String thingID;
    String audience;
    String kid;
    ECDSASigner signer;
    ECKey key;

    public AuthThingSigner(String privateJWK, String thingID, String audience) {
        this.privateJWK = privateJWK;
        this.thingID = thingID;

        if(audience.equals("root")) {
            audience = "/";
        }
        this.audience = audience;
    }

    public String sign(String nonce) throws ParseException, JOSEException {
        if (this.key == null) {
            this.key = ECKey.parse(privateJWK);
            this.signer = new ECDSASigner(key);
            this.kid = key.getKeyID();
        }
        // Create an HMAC-protected JWS object with some payload
        long unixTime = System.currentTimeMillis() / 1000;
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", thingID);
        claims.put("iat", unixTime);
        claims.put("exp", unixTime + 300);
        claims.put("aud", audience);
        claims.put("nonce", nonce);
        Map<String, String> cnf = new HashMap<>();
        cnf.put("kid", kid);
        claims.put("cnf", cnf);

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
