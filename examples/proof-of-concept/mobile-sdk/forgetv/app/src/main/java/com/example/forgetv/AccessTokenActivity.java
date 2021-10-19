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