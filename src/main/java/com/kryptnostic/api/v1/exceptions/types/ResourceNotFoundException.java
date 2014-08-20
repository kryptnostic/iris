package com.kryptnostic.api.v1.exceptions.types;

import retrofit.RetrofitError;

@SuppressWarnings("serial")
public class ResourceNotFoundException extends Exception {

    public ResourceNotFoundException() {

    }

    public ResourceNotFoundException(String msg) {
        super(msg);
    }

    public ResourceNotFoundException(RetrofitError cause) {
        super(cause);
    }

}
