package com.example.forgetv;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.nimbusds.jose.JOSEException;

import org.forgerock.android.auth.FRUser;
import org.forgerock.android.auth.Node;
import org.forgerock.android.auth.NodeListener;
import org.forgerock.android.auth.callback.HiddenValueCallback;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.text.ParseException;

public class AuthenticateActivity extends AppCompatActivity {
    NodeListener listener;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_authenticate);
        Intent intent = new Intent(this, AccessTokenActivity.class);
        final AuthThingSigner authSigner =
                new AuthThingSigner(
                             getResources().getString(R.string.jwt_kid),
                             getResources().getString(R.string.thing_id),
                             getResources().getString(R.string.forgerock_realm));
        NodeListener<FRUser> nodeListenerFuture =
                new NodeListener<FRUser>() {
                    @Override
                    public void onSuccess(FRUser result) {
                        startActivity(intent);
                    }

                    @Override
                    public void onException(Exception e) {
                        e.printStackTrace();
                    }

                    @Override
                    public void onCallbackReceived(Node node) {
                        listener = this;
                        HiddenValueCallback cb = node.getCallback(HiddenValueCallback.class);
                        if (cb != null) {
                            String nonce = cb.getValue();
                            try {
                                String jws = authSigner.sign(nonce);
                                cb.setValue(jws);
                                // call next to move on and send response to AM
                                node.next(AuthenticateActivity.this, this);
                            } catch (ParseException | IOException | JOSEException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
                                e.printStackTrace();
                            }
                        }
                    }
                };

        if (FRUser.getCurrentUser() != null ){
            FRUser.getCurrentUser().logout();
        }
        FRUser.login(this, nodeListenerFuture);
    }
}