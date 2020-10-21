package com.crypho.plugins;

import java.io.File;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import android.annotation.TargetApi;
import android.app.admin.DevicePolicyManager;
import android.content.SharedPreferences;
import android.content.res.Resources;
import android.preference.PreferenceManager;
import android.security.keystore.UserNotAuthenticatedException;
import android.telecom.Call;
import android.util.Log;
import android.util.Base64;
import android.os.Build;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.util.Pair;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaArgs;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.crypto.IllegalBlockSizeException;

public class SecureStorage extends CordovaPlugin {
    private final ExecutorService threadPool = Executors.newCachedThreadPool();
    private static final String TAG = "SecureStorage";

    private static final boolean SUPPORTS_NATIVE_AES = Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP;
    private static final boolean SUPPORTED = Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT;

    private static final String MSG_NOT_SUPPORTED = "API 19 (Android 4.4 KitKat) is required. This device is running API " + Build.VERSION.SDK_INT;
    private static final String MSG_DEVICE_NOT_SECURE = "Device is not secure";
    public static final String MIGRATED_FOR_SECURITY = "_SS_MIGRATED_FOR_SECURITY";

    private final Hashtable<String, SharedPreferencesHandler> SERVICE_STORAGE = new Hashtable<String, SharedPreferencesHandler>();

    private IntentRequestQueue intentRequestQueue;

    @Override
    protected void pluginInitialize() {

        super.pluginInitialize();

        intentRequestQueue = new IntentRequestQueue(this);

    }


    private void securityMigration(CallbackContext callbackContext) throws JSONException {
        Log.e(TAG, "Migration Started");
        //transfer all existing items to new table
        Hashtable<Integer, TransitionValue> transitionTable = new Hashtable<Integer, TransitionValue>();
        Hashtable<String,Boolean> RSAMap= new Hashtable<String, Boolean>();
        Enumeration<String> services = SERVICE_STORAGE.keys();
        boolean error = false;
        while(services.hasMoreElements()){
            String service = services.nextElement();
            //initializing rsakeymapper
            RSAMap.put(service, false);
            SharedPreferencesHandler handler = SERVICE_STORAGE.get(service);
            Set<String> keys = handler.keys();

            for(String key : keys){
                String value = handler.fetch(key);
                ExecutorResult result = decryptHelper(value, service,callbackContext);

                if(result.type != ExecutorResultType.ERROR){
                    TransitionValue t = new TransitionValue(service, key, result.result);
                    SecureRandom i = new SecureRandom();
                    transitionTable.put(i.nextInt(), t);
                }
                else{
                    error = true;
                }
            }
        }

        //Reinsert data with new keys
        Enumeration<Integer> transitionKeys = transitionTable.keys();
        if(!error){
            while(transitionKeys.hasMoreElements()){
                Integer key = transitionKeys.nextElement();
                TransitionValue tv = transitionTable.get(key);

                //RSA key needs to be created for each service
                if(!RSAMap.get(tv.getService())){
                    try{
                        RSA.createKeyPair(getContext(),service2alias(tv.getService()));

                        RSAMap.put(tv.getService(), true);

                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                //the encryptor helper already inserts items into storage
                ExecutorResult result = encrytionHelper(tv.getService(),tv.getKey(), tv.getValue());
                if(result.type == ExecutorResultType.ERROR){
                    error = true;
                }
            }
        }
        if(!error){
            Context ctx = getContext();
            SharedPreferences preferences = ctx.getSharedPreferences(ctx.getPackageName() + "_SM", 0);
            markAsMigrated(preferences);
            Log.d(TAG, "Migration success");
        }

    }

    private boolean isDeviceSecure() {
        KeyguardManager keyguardManager = (KeyguardManager) (getContext().getSystemService(Context.KEYGUARD_SERVICE));
        try {

            // This tries to call isDeviceSecure, which was only added in API 23
            // The method checks if there is a lock screen that requires authentication defined (not None or Swipe)
            // This is preferred to the older method isKeyguardSecure, that also returns true if the SIM card is unlocked
            Method isSecure = null;
            isSecure = keyguardManager.getClass().getMethod("isDeviceSecure");
            return ((Boolean) isSecure.invoke(keyguardManager)).booleanValue();

        } catch (Exception e) {

            // Best effort if the preferred method is unavailable
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

        Log.e("ACTION: ", action);

        boolean result = false;
        switch (action) {
            case "init":
                result = init(args, callbackContext);
                break;
            case "set":
                result = set(args, callbackContext);
                break;
            case "get":
                result = get(args, callbackContext);
                break;
            case "decrypt_rsa":
                result = decrypt_rsa(args, callbackContext);
                break;
            case "encrypt_rsa":
                result = encrypt_rsa(args, callbackContext);
                break;
            case "secureDevice":
                result = secureDevice(callbackContext);
                break;
            case "remove":
                result = remove(args, callbackContext);
                break;
            case "store":
                result = store(args, callbackContext);
                break;
            case "fetch":
                result = fetch(args, callbackContext);
                break;
            case "keys":
                result = keys(args, callbackContext);
                break;
            case "clear":
                result = clear(args, callbackContext);
        }


        return result;
    }

    // Called when a SecureStorage Javascript object is created
    // Returns an error if a lock screen that requires authentication is not defined
    // Creates a private key for an alias based on the name of the store (if it does not exist already)
    private boolean init(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called init action");

        // Get key alias based on the name of the store
        String service = args.getString(0);
        String alias = service2alias(service);

        // Create helper object to manage a SharedPreferences object for the alias
        SharedPreferencesHandler PREFS = new SharedPreferencesHandler(alias + "_SS", getContext());
        putStorage(service, PREFS);

        if(checkForSecurityMigration()){

            try {
                securityMigration(callbackContext);
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }


        if (!isDeviceSecure()) {
            // Lock screen that requires authentication is not defined
            Log.e(TAG, MSG_DEVICE_NOT_SECURE);
            callbackContext.error(MSG_DEVICE_NOT_SECURE);

        } else if (!RSA.isEntryAvailable(alias)) {
            // Key for alias does not exist
            handleLockScreen(IntentRequestType.INIT, service, callbackContext);

        } else {
            // No actions are required to init correctly
            initSuccess(callbackContext);
        }
        return true;
    }

    private boolean checkForSecurityMigration() {
        Context ctx = getContext();
        SharedPreferences preferences = ctx.getSharedPreferences(ctx.getPackageName() + "_SM",0);
        String isMigrated = preferences.getString(MIGRATED_FOR_SECURITY, "");
        //check OS then check if keys exist and migration was done
        if(Build.VERSION.SDK_INT > Build.VERSION_CODES.M){

            int size = initializePreferences();
            if(isMigrated.equals("TRUE")){
                return false;
            }
            //the target case of migration
            else if(size > 0){
                return true;
            }
            //new use, meaning we should put the tag in as to not trigger a unwanted migration
            else{
                markAsMigrated(preferences);
                return false;
            }
        }
        else{
            //nothing to do return false
            return false;
        }
    }

    private void markAsMigrated(SharedPreferences preferences) {

        SharedPreferences.Editor editor = preferences.edit();
        editor.putString(MIGRATED_FOR_SECURITY, "TRUE");
        editor.commit();
    }

    private int initializePreferences() {

        Context ctx = getContext();
        File prefdir = new File(ctx.getApplicationInfo().dataDir,"shared_prefs");
        String[] filenames = prefdir.list();
        int i = 0;
        for(String name : filenames){
            if(name.contains("SS")){
                String alias = name.substring(0, name.length() - 4);
                String service = alias.substring(ctx.getPackageName().length() + 1, alias.length() -3);

                SharedPreferencesHandler PREFS = new SharedPreferencesHandler(alias, getContext());
                putStorage(service, PREFS);
                i+=1;
            }
        }
        return i;
    }

    // Store a key/enc-value pair in SharedPreferences
    // The encryption uses the key with an alias associated with the store name
    private boolean set(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called set action");
        final String service = args.getString(0);
        final String key = args.getString(1);
        final String value = args.getString(2);

        ExecutorResult result = encrytionHelper(service, key, value);

        if(result.type != ExecutorResultType.ERROR){
            callbackContext.success();
        }
        else{
            callbackContext.error(result.result);
        }
        return true;

    }

    private ExecutorResult encrytionHelper(String service, String key, String value) {

        ExecutorResult result;

        EncryptionExecutor encryptionExecutor = new EncryptionExecutor(service, key, value, cordova.getContext());
        Future<ExecutorResult> exec = cordova.getThreadPool().submit(encryptionExecutor);

        try{
            result = exec.get();
            if(result.type == ExecutorResultType.SUCCESS){
                getStorage(service).store(key, result.result);
            }
        } catch (InterruptedException e) {
            result = new ExecutorResult(ExecutorResultType.ERROR,e.getMessage());
        } catch (ExecutionException e) {
            result = new ExecutorResult(ExecutorResultType.ERROR,e.getMessage());
        }
        return result;

    }

    // Get the enc-value associated with a key in SharedPreferences
    // The decryption uses the key with an alias associated with the store name
    private boolean get(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called get action");
        final String service = args.getString(0);
        final String key = args.getString(1);
        String value = getStorage(service).fetch(key);
        if (value != null) {
            ExecutorResult result = decryptHelper(value, service, callbackContext);

            if (result.type != ExecutorResultType.ERROR) {
                callbackContext.success(result.result);
            }else {
                callbackContext.error(result.result);
            }
        } else {
            callbackContext.error("Key [" + key + "] not found.");
        }
        return true;
    }


    private ExecutorResult decryptHelper(String value, String service, CallbackContext callbackContext) throws JSONException {
        JSONObject json = new JSONObject(value);
        final byte[] encKey = Base64.decode(json.getString("key"), Base64.DEFAULT);
        JSONObject data = json.getJSONObject("value");
        final byte[] ct = Base64.decode(data.getString("ct"), Base64.DEFAULT);
        final byte[] iv = Base64.decode(data.getString("iv"), Base64.DEFAULT);
        final byte[] adata = Base64.decode(data.getString("adata"), Base64.DEFAULT);



        DecryptionExecutor decryptionExecutor = new DecryptionExecutor(encKey, service2alias(service), iv, ct, adata);
        Future<ExecutorResult> decryptThread = cordova.getThreadPool().submit(decryptionExecutor);

        //thread blocks here until result
        ExecutorResult decrypted;
        try {
            decrypted = decryptThread.get();
        } catch (InterruptedException e) {
            decrypted = new ExecutorResult(ExecutorResultType.ERROR, e.getMessage());
        } catch (ExecutionException e) {
            decrypted = new ExecutorResult(ExecutorResultType.ERROR, e.getMessage());
        }

        return decrypted;

    }

    // Decrypt a message using the key with an alias associated with the store name
    private boolean decrypt_rsa(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
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

    // Encrypt a message using the key with an alias associated with the store name
    private boolean encrypt_rsa(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
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

    // Check if there is a lock screen that requires authentication defined
    // It gives the user the possibility of defining one if there isn't one
    // Used by the Ciphered Local Storage Plugin at startup
    private boolean secureDevice(CallbackContext callbackContext) {
        Log.v(TAG, "Called secureDevice action");
        handleLockScreen(IntentRequestType.SECURE_DEVICE, null, callbackContext);
        return true;
    }

    // The remaining actions are the SharedPreferences interface
    private boolean remove(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called remove action");
        String service = args.getString(0);
        String key = args.getString(1);
        getStorage(service).remove(key);
        callbackContext.success();
        return true;
    }

    private boolean store(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called store action");
        String service = args.getString(0);
        String key = args.getString(1);
        String value = args.getString(2);
        getStorage(service).store(key, value);
        callbackContext.success();
        return true;
    }

    private boolean fetch(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
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

    private boolean keys(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called keys action");
        String service = args.getString(0);
        callbackContext.success(new JSONArray(getStorage(service).keys()));
        return true;
    }

    private boolean clear(CordovaArgs args, CallbackContext callbackContext) throws JSONException {
        Log.v(TAG, "Called clear action");
        String service = args.getString(0);
        getStorage(service).clear();
        callbackContext.success();
        return true;
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
        cordova.getActivity().runOnUiThread(new Runnable() {
            public void run() {
                Log.v(TAG, "Handling lock screen");

                if (Build.VERSION.SDK_INT >= 29) { // >= Android 10
                    handleLockScreenUsingNoOpOrSetNewPasswordIntent(type, service, callbackContext);
                } else {
                    handleLockScreenUsingUnlockIntent(type, service, callbackContext);
                }
            }
        });
    }

    // Made in context of RNMT-3255, RNMT-3540 and RNMT-3803
    @TargetApi(29)
    private void handleLockScreenUsingNoOpOrSetNewPasswordIntent(IntentRequestType type, String service, CallbackContext callbackContext) {
        Log.v(TAG, "Handling lock screen via no action or ACTION_SET_NEW_PASSWORD intent (Android 10 or newer)");

        if (isDeviceSecure()) {
            Log.v(TAG, "Unlocking Android devices above 10 using Keyguard manager");
            KeyguardManager keyguardManager = (KeyguardManager) (getContext().getSystemService(Context.KEYGUARD_SERVICE));
            Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
            // Lock screen is already defined, carry on without using an intent
            intentRequestQueue.queueRequest(type, service, intent, callbackContext);

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
