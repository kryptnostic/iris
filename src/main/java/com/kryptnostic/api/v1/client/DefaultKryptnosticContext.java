package com.kryptnostic.api.v1.client;

import java.util.List;

import cern.colt.bitvector.BitVector;

import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.linear.BitUtils;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

public class DefaultKryptnosticContext implements KryptnosticContext {

    private SimplePolynomialFunction indexingHashFunction;

    private static final int TOKEN_LENGTH = 256;
    private static final int LOCATION_LENGTH = 64;
    private static final int NONCE_LENGTH = 64;

    @Override
    public SimplePolynomialFunction getSearchFunction() {
        if (indexingHashFunction == null) {
            indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH, NONCE_LENGTH, LOCATION_LENGTH);
            // TODO POST to search function service
        }
        return indexingHashFunction;
    }

    @Override
    public List<BitVector> getNonces() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void addNonces(List<BitVector> nonces) {
        // TODO Auto-generated method stub

    }

    public BitVector generateNonce() {
        return BitUtils.randomVector(NONCE_LENGTH);
    }

}
