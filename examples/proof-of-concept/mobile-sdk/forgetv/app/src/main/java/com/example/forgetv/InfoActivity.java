package com.example.forgetv;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;

import org.json.JSONObject;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.ECPublicKey;

public class InfoActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_info);
        TextView idTxt = findViewById(R.id.textViewInfo);
        idTxt.setText(getResources().getString(R.string.thing_id));
        try {
            // read public key from keystore
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PublicKey publicKey = keyStore.getCertificate("forgerock").getPublicKey();
            ECKey esKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                    .keyID(getResources().getString(R.string.jwt_kid))
                    .keyUse(KeyUse.SIGNATURE)
                    .build();

            // write key in a JWK Set
            String jwkSet = String.format("{\"keys\":[%s]}", new JSONObject(esKey.toJSONObject()));
            TextView jwkTxt = findViewById(R.id.textJWK);
            jwkTxt.setText(jwkSet);

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        }

    }

    public void refresh(View view){
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }
}