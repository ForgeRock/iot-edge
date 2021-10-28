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

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import org.spongycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.BasicConstraints;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.asn1.x509.ExtensionsGenerator;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class CertificateSigningRequestActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_csr);
        TextView certView = findViewById(R.id.cert);
        try {
            // read public key from keystore
            KeyStore keyStore = KeyStore.getInstance(AbstractJWTSigner.PROVIDER);
            keyStore.load(null);

            PublicKey publicKey = keyStore.getCertificate(AbstractJWTSigner.KEY_ALIAS).getPublicKey();
            //Generate CSR in PKCS#10 format encoded in DER
            String principal = String.format("CN=%s", getResources().getString(R.string.thing_id));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build((PrivateKey) keyStore.getKey("forgerock", null));

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(principal), publicKey);
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(
                    true));
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensionsGenerator.generate());
            PKCS10CertificationRequest csr = csrBuilder.build(signer);
            byte  CSRder[] = csr.getEncoded();
            String csrString = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    Base64.encodeToString(CSRder, Base64.DEFAULT) +
                    "-----END CERTIFICATE REQUEST-----";
            TextView v = findViewById(R.id.csr);
            v.setText(csrString);

            ExecutorService executor = Executors.newSingleThreadExecutor();
            Handler handler = new Handler(Looper.getMainLooper());

            executor.execute(new Runnable() {
                @Override
                public void run() {

                    //Background work here
                    final MediaType JSON
                            = MediaType.get("application/json; charset=utf-8");

                    OkHttpClient client = new OkHttpClient();

                    RequestBody body = RequestBody.create(JSON, csrString);
                    Request request = new Request.Builder()
                            .url("http://10.0.2.2:8088/sign")
                            .post(body)
                            .build();
                    Response response;
                    try {
                        response = client.newCall(request).execute();
//                        String responseBody = response.body().string();
                        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(response.body().bytes());
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inputStream);
                        keyStore.setCertificateEntry(AbstractJWTSigner.CERT_ALIAS, cert);
                        handler.post(new Runnable() {
                            @Override
                            public void run() {
                                //UI Thread work here
//                                certView.setText(responseBody);
                            }
                        });
                    } catch (IOException | CertificateException | KeyStoreException e) {
                        e.printStackTrace();
                    }

                }
            });

        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | OperatorCreationException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

    }

    public void refresh(View view){
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }
}