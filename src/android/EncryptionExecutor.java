package com.crypho.plugins;

import android.content.Context;
import android.util.Base64;
import android.util.Log;
import org.json.JSONException;
import org.json.JSONObject;
import java.util.concurrent.Callable;

public class EncryptionExecutor implements Callable<ExecutorResult>
{
    private static final String TAG = "SecureStorage";
    private String service, key, value;
    private Context context;

    public EncryptionExecutor(String service, String key, String value, Context context){
        
        this.service = service;
        this.key = key;
        this.value = value;
        this.context = context;
    }
    @Override
    public ExecutorResult call() throws JSONException {
        try {
            JSONObject result = AES.encrypt(value.getBytes(), service.getBytes());
            byte[] aes_key = Base64.decode(result.getString("key"), Base64.DEFAULT);
            byte[] aes_key_enc = RSA.encrypt(aes_key, service2alias(service));
            result.put("key", Base64.encodeToString(aes_key_enc, Base64.DEFAULT));


            return new ExecutorResult(ExecutorResultType.SUCCESS,result.toString());
        } catch (Exception e) {
            Log.e(TAG, "Encrypt (RSA/AES) failed :", e);


            return new ExecutorResult(ExecutorResultType.ERROR,e.getMessage());
        }
    }

    private String service2alias(String service) {
        return context.getPackageName() + "." + service;
    }
}