package com.kryptnostic.mock.services;

import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class MockSearchFunctionService implements SearchFunctionApi {
    private SimplePolynomialFunction searchFunction;
    private final Integer OK_STATUS = 200;

    
    @Override
    public BasicResponse<Boolean> setFunction(SimplePolynomialFunction function) {
        searchFunction = function;
        return new BasicResponse<Boolean>(true, OK_STATUS, true);
    }

    @Override
    public BasicResponse<SimplePolynomialFunction> getFunction() throws ResourceNotFoundException {
        if (searchFunction == null) {
            throw new ResourceNotFoundException();
        }
        return new BasicResponse<SimplePolynomialFunction>(searchFunction, OK_STATUS, true);
    }

}
