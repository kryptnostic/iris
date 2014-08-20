package com.kryptnostic.api.v1.exceptions.types;

import retrofit.RetrofitError;

@SuppressWarnings("serial")
public class BadRequestException extends Exception {
    public BadRequestException() {

    }

    public BadRequestException(String msg) {
        super(msg);
    }

    public BadRequestException(RetrofitError cause) {
        super(cause);
    }
}
