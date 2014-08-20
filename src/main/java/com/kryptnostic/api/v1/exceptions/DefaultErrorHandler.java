package com.kryptnostic.api.v1.exceptions;

import retrofit.ErrorHandler;
import retrofit.RetrofitError;
import retrofit.client.Response;

import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.exceptions.types.UnauthorizedException;

public class DefaultErrorHandler implements ErrorHandler {
    @Override
    public Throwable handleError(RetrofitError cause) {
        Response r = cause.getResponse();
        if (r != null && r.getStatus() == 401) {
            return new UnauthorizedException(cause);
        }
        if (r != null && r.getStatus() == 404) {
            return new ResourceNotFoundException(cause);
        }
        if (r != null && r.getStatus() == 400) {
            return new BadRequestException(cause);
        }
        return cause;
    }
}
