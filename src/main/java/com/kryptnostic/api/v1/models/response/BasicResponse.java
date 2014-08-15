package com.kryptnostic.api.v1.models.response;

/**
 * Immutable basic response model for web services http://wiki.krypt.local/display/PS/Basic+Response+Model
 * 
 * @author sina
 */
public class BasicResponse<T> {
    protected T data;
    protected int status;
    protected boolean success;

    public BasicResponse() {

    }

    public BasicResponse(T data, int status, boolean success) {
        this.data = data;
        this.status = status;
        this.success = success;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

}
