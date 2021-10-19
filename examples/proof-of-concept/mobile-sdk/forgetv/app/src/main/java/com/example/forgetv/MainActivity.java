package com.example.forgetv;

import android.content.Intent;
import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import com.nimbusds.jose.JOSEException;

import org.forgerock.android.auth.FRUser;
import org.forgerock.android.auth.Node;
import org.forgerock.android.auth.NodeListener;
import org.forgerock.android.auth.callback.HiddenValueCallback;

import java.text.ParseException;

public class MainActivity extends AppCompatActivity {
    NodeListener listener;
    final String privateJWK = "{\"use\":\"sig\",\"kty\":\"EC\",\"kid\":\"pop.cnf\",\"crv\":\"P-256\",\"x\":\"wjC9kMzwIeXNn6lsjdqplcq9aCWpAOZ0af1_yruCcJ4\",\"y\":\"ihIziCymBnU8W8m5zx69DsQr0sWDiXsDMq04lBmfEHw\",\"d\":\"BnNIPPqc64q7gXm4N7WFNqDMEOLQ2BvCzUbL5w3RPtg\"}";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Intent intent = new Intent(this, AccessTokenActivity.class);
        final AuthThingSigner authSigner =
                new AuthThingSigner(
                            privateJWK,
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
                                node.next(MainActivity.this, this);
                            } catch (ParseException e) {
                                e.printStackTrace();
                            } catch (JOSEException e) {
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