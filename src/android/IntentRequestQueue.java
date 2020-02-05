package com.crypho.plugins;

import android.content.Intent;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;

import java.util.ArrayList;
import java.util.List;

// Enforces that only one intent is handled at a time
class IntentRequestQueue {

    private final Object LOCK = new Object();

    private final CordovaPlugin plugin;
    private final List<IntentRequest> requests;

    IntentRequestQueue(CordovaPlugin plugin) {
        this.plugin = plugin;
        this.requests = new ArrayList<IntentRequest>();
    }

    void queueRequest(IntentRequestType type, String service, Intent intent, CallbackContext context) {
        IntentRequest request = new IntentRequest(type, service, intent, context);
        this.queueRequest(request);
    }

    void queueRequest(IntentRequest request) {
        synchronized (LOCK) {

            // Adds the request
            this.requests.add(request);

            // If the new request is the only request then handle it
            if (this.requests.size() == 1) {
                handleHeadRequest();
            }
        }
    }

    // Should be called in onActivityResult
    IntentRequest notifyActivityResultCalled() {
        synchronized (LOCK) {

            // Remove the request (it already finished being handled)
            IntentRequest request = this.requests.remove(0);

            // If there are more requests then handle the first one
            if (this.requests.size() > 0) {
                handleHeadRequest();
            }

            return request;
        }
    }

    // Handles the first request
    private void handleHeadRequest() {
        IntentRequest request = this.requests.get(0);
        Intent intent = request.getIntent();

        CordovaInterface cordova = this.plugin.cordova;
        cordova.startActivityForResult(this.plugin, intent, 0);
    }
}
