package com.kryptnostic.api.v1.exceptions.types;

import retrofit.RetrofitError;

@SuppressWarnings("serial")
public class UnauthorizedException extends Exception {

    public UnauthorizedException(RetrofitError cause) {
        super(cause);
    }

}
