package com.kryptnostic.mock.services;

import java.util.Collection;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.storage.v1.client.NonceApi;

public class MockNonceService implements NonceApi {
    private final Collection<BitVector> nonces = Lists.newArrayList();
    private final Integer OK_STATUS = 200;
    
    @Override
    public BasicResponse<Boolean> addNonces(Collection<BitVector> nonces) {
        this.nonces.addAll(nonces);
        return new BasicResponse<Boolean>(true, OK_STATUS, true);
    }

    @Override
    public BasicResponse<Collection<BitVector>> getNonces() {
        return new BasicResponse<Collection<BitVector>>(nonces, OK_STATUS, true);
    }

}
