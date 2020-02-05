package com.crypho.plugins;

import java.lang.reflect.Method;
import java.util.Hashtable;

import android.app.admin.DevicePolicyManager;
import android.util.Log;
import android.util.Base64;
import android.os.Build;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

public class SecureStorage extends CordovaPlugin {
    private static final String TAG = "SecureStorage";

    private static final boolean SUPPORTS_NATIVE_AES = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
    private static final boolean SUPPORTED = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;

    private static final String MSG_NOT_SUPPORTED = "API 19 (Android 4.4 KitKat) is required. This device is running API " + Build.VERSION.SDK_INT;
    private static final String MSG_DEVICE_NOT_SECURE = "Device is not secure";

    private final Hashtable<String, SharedPreferencesHandler> SERVICE_STORAGE = new Hashtable<String, SharedPreferencesHandler>();

    private IntentRequestQueue intentRequestQueue;

    @Override
    protected void pluginInitialize() {
        super.pluginInitialize();

        intentRequestQueue = new IntentRequestQueue(this);
    }

    private boolean isDeviceSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) (getContext().getSystemService(Context.KEYGUARD_SERVICE));
        try {
            Method isSecure = null;
            isSecure = keyguardManager.getClass().getMethod("isDeviceSecure");
            return ((Boolean) isSecure.invoke(keyguardManager)).booleanValue();
        } catch (Exception e) {
            return keyguardManager.isKeyguardSecure();
        }
    }

    @Override
    public boolean execute(String action, CordovaArgs args, final CallbackContext callbackContext) throws JSONException {
        if (!SUPPORTED) {
            Log.w(TAG, MSG_NOT_SUPPORTED);
            callbackContext.error(MSG_NOT_SUPPORTED);
            return false;
        }
        if ("init".equals(action)) {
            String service = args.getString(0);
            String alias = service2alias(service);

            SharedPreferencesHandler PREFS = new SharedPreferencesHandler(alias + "_SS", getContext());
            putStorage(service, PREFS);

            if (!isDeviceSecure()) {
                Log.e(TAG, MSG_DEVICE_NOT_SECURE);
                callbackContext.error(MSG_DEVICE_NOT_SECURE);
            } else if (!RSA.isEntryAvailable(alias)) {
                unlockCredentials(IntentRequestType.INIT, service, callbackContext);
            } else {
                initSuccess(callbackContext);
            }
            return true;
        }
        if ("set".equals(action)) {
            final String service = args.getString(0);
            final String key = args.getString(1);
            final String value = args.getString(2);
            final String adata = service;
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        JSONObject result = AES.encrypt(value.getBytes(), adata.getBytes());
                        byte[] aes_key = Base64.decode(result.getString("key"), Base64.DEFAULT);
                        byte[] aes_key_enc = RSA.encrypt(aes_key, service2alias(service));
                        result.put("key", Base64.encodeToString(aes_key_enc, Base64.DEFAULT));
                        getStorage(service).store(key, result.toString());
                        callbackContext.success();
                    } catch (Exception e) {
                        Log.e(TAG, "Encrypt (RSA/AES) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        if ("get".equals(action)) {
            final String service = args.getString(0);
            final String key = args.getString(1);
            String value = getStorage(service).fetch(key);
            if (value != null) {
                JSONObject json = new JSONObject(value);
                final byte[] encKey = Base64.decode(json.getString("key"), Base64.DEFAULT);
                JSONObject data = json.getJSONObject("value");
                final byte[] ct = Base64.decode(data.getString("ct"), Base64.DEFAULT);
                final byte[] iv = Base64.decode(data.getString("iv"), Base64.DEFAULT);
                final byte[] adata = Base64.decode(data.getString("adata"), Base64.DEFAULT);
                cordova.getThreadPool().execute(new Runnable() {
                    public void run() {
                        try {
                            byte[] decryptedKey = RSA.decrypt(encKey, service2alias(service));
                            String decrypted = new String(AES.decrypt(ct, decryptedKey, iv, adata));
                            callbackContext.success(decrypted);
                        } catch (Exception e) {
                            Log.e(TAG, "Decrypt (RSA/AES) failed :", e);
                            callbackContext.error(e.getMessage());
                        }
                    }
                });
            } else {
                callbackContext.error("Key [" + key + "] not found.");
            }
            return true;
        }
        if ("decrypt_rsa".equals(action)) {
            final String service = args.getString(0);
            // getArrayBuffer does base64 decoding
            final byte[] decryptMe = args.getArrayBuffer(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] decrypted = RSA.decrypt(decryptMe, service2alias(service));
                        callbackContext.success(new String(decrypted));
                    } catch (Exception e) {
                        Log.e(TAG, "Decrypt (RSA) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }
        if ("encrypt_rsa".equals(action)) {
            final String service = args.getString(0);
            final String encryptMe = args.getString(1);
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        byte[] encrypted = RSA.encrypt(encryptMe.getBytes(), service2alias(service));
                        callbackContext.success(Base64.encodeToString(encrypted, Base64.DEFAULT));
                    } catch (Exception e) {
                        Log.e(TAG, "Encrypt (RSA) failed :", e);
                        callbackContext.error(e.getMessage());
                    }
                }
            });
            return true;
        }

        if ("secureDevice".equals(action)) {
            unlockCredentials(IntentRequestType.SECURE_DEVICE, null, callbackContext);
            return true;
        }
        //SharedPreferences interface
        if ("remove".equals(action)) {
            String service = args.getString(0);
            String key = args.getString(1);
            getStorage(service).remove(key);
            callbackContext.success();
            return true;
        }
        if ("store".equals(action)) {
            String service = args.getString(0);
            String key = args.getString(1);
            String value = args.getString(2);
            getStorage(service).store(key, value);
            callbackContext.success();
            return true;
        }
        if ("fetch".equals(action)) {
            String service = args.getString(0);
            String key = args.getString(1);
            String value = getStorage(service).fetch(key);
            if (value != null) {
                callbackContext.success(value);
            } else {
                callbackContext.error("Key [" + key + "] not found.");
            }
            return true;
        }
        if ("keys".equals(action)) {
            String service = args.getString(0);
            callbackContext.success(new JSONArray(getStorage(service).keys()));
            return true;
        }
        if ("clear".equals(action)) {
            String service = args.getString(0);
            getStorage(service).clear();
            callbackContext.success();
            return true;
        }
        return false;
    }

    private String service2alias(String service) {
        String res = getContext().getPackageName() + "." + service;
        return res;
    }

    private SharedPreferencesHandler getStorage(String service) {
        synchronized (SERVICE_STORAGE) {
            return SERVICE_STORAGE.get(service);
        }
    }

    private void putStorage(String service, SharedPreferencesHandler handler) {
        synchronized (SERVICE_STORAGE) {
            SERVICE_STORAGE.put(service, handler);
        }
    }

    private void initSuccess(CallbackContext context) {
        // 0 is falsy in js while 1 is truthy
        context.success(SUPPORTS_NATIVE_AES ? 1 : 0);
    }

    private void unlockCredentials(final IntentRequestType type, final String service, final CallbackContext callbackContext) {
        cordova.getActivity().runOnUiThread(new Runnable() {
            public void run() {

                if (Build.VERSION.SDK_INT > 28) {
                    unlockCredentialsUsingKeyguardManager(type, service, callbackContext);
                } else {
                    unlockCredentialsUsingUnlockIntent(type, service, callbackContext);
                }
            }
        });
    }

    // Made in context of RNMT-3255 and RNMT-3540
    private void unlockCredentialsUsingKeyguardManager(IntentRequestType type, String service, CallbackContext callbackContext) {
        KeyguardManager keyguardManager = (KeyguardManager) (getContext().getSystemService(Context.KEYGUARD_SERVICE));
        Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);

        if (intent == null) {
            intent = new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
        }

        intentRequestQueue.queueRequest(type, service, intent, callbackContext);
    }

    private void unlockCredentialsUsingUnlockIntent(IntentRequestType type, String service, CallbackContext callbackContext) {
        Intent intent = new Intent("com.android.credentials.UNLOCK");
        intentRequestQueue.queueRequest(type, service, intent, callbackContext);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        super.onActivityResult(requestCode, resultCode, intent);

        IntentRequest request = intentRequestQueue.notifyActivityResultCalled();
        CallbackContext callbackContext = request.getCallbackContext();

        switch (request.getType()) {
            case INIT:
                completeInit(request.getService(), callbackContext);
                break;

            case SECURE_DEVICE:
                completeSecureDevice(callbackContext);
                break;
        }
    }

    private void completeInit(final String service, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    // RSA already has mutual exclusion in all its public methods individually
                    // But this block requires mutual exclusion as a whole
                    synchronized (SecureStorage.this) {
                        String alias = service2alias(service);
                        if (!RSA.isEntryAvailable(alias)) {
                            //Solves Issue #96. The RSA key may have been deleted by changing the lock type.
                            getStorage(service).clear();
                            RSA.createKeyPair(getContext(), alias);
                        }
                    }
                    initSuccess(callbackContext);
                } catch (Exception e) {
                    Log.e(TAG, "Init failed :", e);
                    callbackContext.error(e.getMessage());
                }
            }
        });
    }

    private void completeSecureDevice(CallbackContext callbackContext) {
        if (isDeviceSecure()) {
            callbackContext.success();
        } else {
            callbackContext.error(MSG_DEVICE_NOT_SECURE);
        }
    }

    private Context getContext() {
        return cordova.getActivity().getApplicationContext();
    }
}
