package com.crypho.plugins;

public class ExecutorResult{
    public ExecutorResultType type;
    public String result;
    public ExecutorResult(ExecutorResultType type, String result){
        this.type = type;
        this.result = result;
    }
}
