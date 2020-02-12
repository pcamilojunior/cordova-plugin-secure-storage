package com.crypho.plugins;

import android.content.Intent;

import org.apache.cordova.CallbackContext;

class IntentRequest {

    private IntentRequestType type;
    private String service;
    private Intent intent;
    private CallbackContext context;

    IntentRequest(IntentRequestType type, String service, Intent intent, CallbackContext context) {
        this.type = type;
        this.service = service;
        this.intent = intent;
        this.context = context;
    }

    IntentRequestType getType() {
        return type;
    }

    String getService() {
        return service;
    }

    Intent getIntent() {
        return intent;
    }

    CallbackContext getCallbackContext() {
        return context;
    }
}
