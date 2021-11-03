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

import static com.nimbusds.jose.util.Base64URL.from;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.nimbusds.jose.JWSObject;

import org.forgerock.android.auth.AccessToken;
import org.forgerock.android.auth.FRListener;
import org.forgerock.android.auth.FRUser;
import org.json.JSONException;
import org.json.JSONObject;

import java.text.ParseException;

public class AccessTokenActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_accesstoken);
        TextView accessTokenTxt = findViewById(R.id.textViewAccessToken);
        FRUser.getCurrentUser().getAccessToken(new FRListener<AccessToken>() {
            @Override
            public void onSuccess(AccessToken result) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            String value = result.getValue();
                            String[] token = value.split("\\.");

                            if (token.length == 3) {
                                JWSObject jwt = new JWSObject(
                                        from(token[0]),
                                        from(token[1]),
                                        from(token[2]));
                                JSONObject obj = new JSONObject(jwt.getPayload().toJSONObject());
                                value = obj.toString(4);
                            }

                            accessTokenTxt.setText(value);
                        } catch (JSONException | ParseException e) {
                            e.printStackTrace();
                        }
                    }
                });
            }

            @Override
            public void onException(Exception e) {

            }
        });
    }

    public void refresh(View view){
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
    }
}