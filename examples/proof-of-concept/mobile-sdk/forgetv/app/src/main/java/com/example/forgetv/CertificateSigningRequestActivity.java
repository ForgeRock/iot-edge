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

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
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
    final String errorMessageKey = "err";
    final String certMessageKey = "cert";
    final int certMessageType = 1;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_csr);
        TextView v = findViewById(R.id.csr);
        Context context = this;
        Handler handler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                Bundle bb = msg.getData();
                if (msg.what == certMessageType){
                    v.append(String.format("ADDED TO KEYSTORE:\n\n%s",
                            bb.getString(certMessageKey)));
                    findViewById(R.id.progressBar2).setVisibility(View.INVISIBLE);
                    findViewById(R.id.refreshButton).setVisibility(View.VISIBLE);
                } else {
                    String str = bb.getString(errorMessageKey);
                    AlertDialog.Builder builder = new AlertDialog.Builder(context);
                    builder.setNeutralButton(R.string.return_button, (dialog, which) -> {
                                Intent intent = new Intent(context, MainActivity.class);
                                startActivity(intent);
                            }

                    ).setMessage(str).setTitle("Error");
                    builder.create().show();
                }
            }
        };
        try {
            // read public key from keystore
            KeyStore keyStore = KeyStore.getInstance(AbstractJWTSigner.PROVIDER);
            keyStore.load(null);

            PublicKey publicKey = keyStore.getCertificate(AbstractJWTSigner.KEY_ALIAS).getPublicKey();
            //Generate CSR in PKCS#10 format encoded in DER
            String principal = String.format("CN=%s", getResources().getString(R.string.thing_id));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
                    .build((PrivateKey) keyStore.getKey("forgerock", null));

            PKCS10CertificationRequestBuilder csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                    new X500Name(principal), publicKey);
            ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
            extensionsGenerator.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(true));
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensionsGenerator.generate());
            PKCS10CertificationRequest csr = csrBuilder.build(signer);
            byte[] encodedCSR = csr.getEncoded();
            String csrString = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                    Base64.encodeToString(encodedCSR, Base64.DEFAULT) +
                    "-----END CERTIFICATE REQUEST-----";
            v.setText(String.format("%s\n\n", csrString));

            ExecutorService executor = Executors.newSingleThreadExecutor();

            executor.execute(new Runnable() {
                @Override
                public void run() {
                    OkHttpClient client = new OkHttpClient();

                    Request request = new Request.Builder()
                            .url(getResources().getString(R.string.dunny_ca_url))
                            .post(RequestBody.create(csrString, MediaType.get("application/x-pem-file")))
                            .build();
                    Response response;
                    try {
                        response = client.newCall(request).execute();
                        ByteArrayInputStream inputStream  =  new ByteArrayInputStream(response.body().bytes());
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate)certFactory.generateCertificate(inputStream);
                        keyStore.setCertificateEntry(AbstractJWTSigner.CERT_ALIAS, cert);
                        Message m = Message.obtain();
                        m.what = certMessageType;
                        Bundle b = new Bundle();
                        b.putString(certMessageKey, cert.toString());
                        m.setData(b);
                        handler.sendMessage(m);
                    } catch (IOException | CertificateException | KeyStoreException e) {
                        e.printStackTrace();
                        Message m = Message.obtain();
                        Bundle b = new Bundle();
                        b.putString(errorMessageKey, e.getMessage());
                        m.setData(b);
                        handler.sendMessage(m);
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