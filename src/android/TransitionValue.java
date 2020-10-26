package com.crypho.plugins;

public  class TransitionValue{
    private String service, key, value;

    public  TransitionValue(String service, String key, String value){
        this.service = service;
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public String getService() {
        return service;
    }

    public String getValue() {
        return value;
    }
}