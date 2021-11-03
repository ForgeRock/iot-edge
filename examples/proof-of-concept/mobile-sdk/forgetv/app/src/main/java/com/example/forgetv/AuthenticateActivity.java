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
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.view.View;

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
        final RegThingSigner regSigner =
                new RegThingSigner(
                        getResources().getString(R.string.jwt_kid),
                        getResources().getString(R.string.thing_id),
                        getResources().getString(R.string.forgerock_realm));

        Context context = this;
        Handler handler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                Bundle bb = msg.getData();
                String str = bb.getString("err");
                AlertDialog.Builder builder = new AlertDialog.Builder(context);
                builder.setNeutralButton(R.string.return_button, (dialog, which) -> {
                    Intent intent = new Intent(context, MainActivity.class);
                    startActivity(intent);
                }

                ).setMessage(str).setTitle("Error");
                builder.create().show();
            }
        };

        NodeListener<FRUser> nodeListenerFuture =
                new NodeListener<FRUser>() {
                    @Override
                    public void onSuccess(FRUser result) {
                        startActivity(intent);
                    }

                    @Override
                    public void onException(Exception e) {
                        e.printStackTrace();
                        Message m = Message.obtain();
                        Bundle b = new Bundle();
                        b.putString("err", e.getMessage());
                        m.setData(b);
                        handler.sendMessage(m);

                    }

                    @Override
                    public void onCallbackReceived(Node node) {
                        listener = this;
                        HiddenValueCallback cb = node.getCallback(HiddenValueCallback.class);
                        if (cb != null) {
                            String nonce = cb.getValue();
                            try {
                                String response;
                                switch (cb.getId()) {
                                    case "jwt-pop-authentication":
                                        response = authSigner.sign(nonce);
                                        break;
                                    case "jwt-pop-registration":
                                        response = regSigner.sign(nonce);
                                        break;
                                    default:
                                        return;
                                }

                                cb.setValue(response);
                                // call next to move on and send response to AM
                                node.next(AuthenticateActivity.this, this);
                            } catch (Exception e) {
                                e.printStackTrace();
                                onException(e);
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