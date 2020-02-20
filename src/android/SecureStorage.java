package com.crypho.plugins;

import java.lang.reflect.Method;
import java.util.Hashtable;

import android.annotation.TargetApi;
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
            Log.v(TAG, "Called init action");
            String service = args.getString(0);
            String alias = service2alias(service);

            SharedPreferencesHandler PREFS = new SharedPreferencesHandler(alias + "_SS", getContext());
            putStorage(service, PREFS);

            if (!isDeviceSecure()) {
                Log.e(TAG, MSG_DEVICE_NOT_SECURE);
                callbackContext.error(MSG_DEVICE_NOT_SECURE);
            } else if (!RSA.isEntryAvailable(alias)) {
                handleLockScreen(IntentRequestType.INIT, service, callbackContext);
            } else {
                initSuccess(callbackContext);
            }
            return true;
        }
        if ("set".equals(action)) {
            Log.v(TAG, "Called set action");
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
            Log.v(TAG, "Called get action");
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
            Log.v(TAG, "Called decrypt_rsa action");
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
            Log.v(TAG, "Called encrypt_rsa action");
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
            Log.v(TAG, "Called secureDevice action");
            handleLockScreen(IntentRequestType.SECURE_DEVICE, null, callbackContext);
            return true;
        }
        //SharedPreferences interface
        if ("remove".equals(action)) {
            Log.v(TAG, "Called remove action");
            String service = args.getString(0);
            String key = args.getString(1);
            getStorage(service).remove(key);
            callbackContext.success();
            return true;
        }
        if ("store".equals(action)) {
            Log.v(TAG, "Called store action");
            String service = args.getString(0);
            String key = args.getString(1);
            String value = args.getString(2);
            getStorage(service).store(key, value);
            callbackContext.success();
            return true;
        }
        if ("fetch".equals(action)) {
            Log.v(TAG, "Called fetch action");
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
            Log.v(TAG, "Called keys action");
            String service = args.getString(0);
            callbackContext.success(new JSONArray(getStorage(service).keys()));
            return true;
        }
        if ("clear".equals(action)) {
            Log.v(TAG, "Called clear action");
            String service = args.getString(0);
            getStorage(service).clear();
            callbackContext.success();
            return true;
        }
        return false;
    }

    private String service2alias(String service) {
        return getContext().getPackageName() + "." + service;
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

    private void handleLockScreen(final IntentRequestType type, final String service, final CallbackContext callbackContext) {
        Log.v(TAG, "Handling lock screen");

        cordova.getActivity().runOnUiThread(new Runnable() {
            public void run() {

                if (Build.VERSION.SDK_INT >= 29) {
                    handleLockScreenUsingKeyguardManagerAndSetNewPasswordIntent(type, service, callbackContext);
                } else {
                    handleLockScreenUsingUnlockIntent(type, service, callbackContext);
                }
            }
        });
    }

    // Made in context of RNMT-3255, RNMT-3540 and RNMT-3803
    @TargetApi(29)
    private void handleLockScreenUsingKeyguardManagerAndSetNewPasswordIntent(IntentRequestType type, String service, CallbackContext callbackContext) {
        Log.v(TAG, "Handling lock screen via KeyguardManager and ACTION_SET_NEW_PASSWORD intent (Android 10 or newer)");

        KeyguardManager keyguardManager = (KeyguardManager) (getContext().getSystemService(Context.KEYGUARD_SERVICE));
        Intent unlockIntent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);

        if (unlockIntent != null) {
            Log.v(TAG, "Lock screen is defined, no unlock action is performed in Android 10 or newer");

            // Lock screen is already defined, carry on without using an intent
            handleCompletedRequest(type, service, callbackContext);

        } else {
            Log.v(TAG, "Lock screen is not defined, requesting one via ACTION_SET_NEW_PASSWORD intent");

            // Lock screen is not defined, so we request a new one
            Intent intent = new Intent(DevicePolicyManager.ACTION_SET_NEW_PASSWORD);
            intentRequestQueue.queueRequest(type, service, intent, callbackContext);
        }
    }

    private void handleLockScreenUsingUnlockIntent(IntentRequestType type, String service, CallbackContext callbackContext) {
        Log.v(TAG, "Handling lock screen via UNLOCK intent (Android 9 or earlier)");

        // Requests a new lock screen or requests to unlock if required
        Intent intent = new Intent("com.android.credentials.UNLOCK");
        intentRequestQueue.queueRequest(type, service, intent, callbackContext);
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        Log.v(TAG, "Activity started by intent has finished");

        super.onActivityResult(requestCode, resultCode, intent);

        IntentRequest request = intentRequestQueue.notifyActivityResultCalled();

        IntentRequestType type = request.getType();
        String service = request.getService();
        CallbackContext callbackContext = request.getCallbackContext();

        handleCompletedRequest(type, service, callbackContext);
    }

    private void handleCompletedRequest(IntentRequestType type, String service, CallbackContext callbackContext) {
        Log.v(TAG, "Request has completed (maybe from an intent)");

        switch (type) {

            case INIT:
                handleCompletedInit(service, callbackContext);
                break;

            case SECURE_DEVICE:
                handleCompletedSecureDevice(callbackContext);
                break;

            default:
                Log.w(TAG, "Request completion was not handled");
                break;
        }
    }

    private void handleCompletedInit(final String service, final CallbackContext callbackContext) {
        cordova.getThreadPool().execute(new Runnable() {
            public void run() {
                try {
                    // RSA already has mutual exclusion in all its public methods individually
                    // But this block requires mutual exclusion as a whole
                    synchronized (SecureStorage.this) {
                        Log.v(TAG, "Completed request is of init action");

                        String alias = service2alias(service);
                        if (!RSA.isEntryAvailable(alias)) {
                            //Solves Issue #96. The RSA key may have been deleted by changing the lock type.
                            getStorage(service).clear();
                            RSA.createKeyPair(getContext(), alias);
                        }
                    }

                    Log.v(TAG, "init returned success");
                    initSuccess(callbackContext);

                } catch (Exception e) {
                    Log.e(TAG, "Init returned error because: ", e);
                    callbackContext.error(e.getMessage());
                }
            }
        });
    }

    private void handleCompletedSecureDevice(CallbackContext callbackContext) {
        Log.v(TAG, "Completed request is of secureDevice action");

        if (isDeviceSecure()) {
            Log.v(TAG, "secureDevice returned success");
            callbackContext.success();

        } else {
            Log.v(TAG, "secureDevice returned error");
            callbackContext.error(MSG_DEVICE_NOT_SECURE);
        }
    }

    private Context getContext() {
        return cordova.getActivity().getApplicationContext();
    }
}
