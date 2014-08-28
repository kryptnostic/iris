package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.linear.BitUtils;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.NonceApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final NonceApi nonceService;
    private final SearchFunctionApi searchFunctionService;

    private SimplePolynomialFunction indexingHashFunction;

    private static final Logger log = LoggerFactory.getLogger(DefaultKryptnosticContext.class);

    private static final int TOKEN_LENGTH = 256;
    private static final int LOCATION_LENGTH = 64;
    private static final int NONCE_LENGTH = 64;

    public DefaultKryptnosticContext(SearchFunctionApi searchFunctionService, NonceApi nonceService) {
        this.searchFunctionService = searchFunctionService;
        this.nonceService = nonceService;
    }

    @Override
    public SimplePolynomialFunction getSearchFunction() {
        if (indexingHashFunction == null) {
            try {
                indexingHashFunction = searchFunctionService.getFunction().getData();
            } catch (ResourceNotFoundException e) {
                // no search function was stored remotely
            }
            if (indexingHashFunction == null) {
                indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH, NONCE_LENGTH,
                        LOCATION_LENGTH);
                searchFunctionService.setFunction(indexingHashFunction);
            }
        }
        return indexingHashFunction;
    }

    @Override
    public List<BitVector> getNonces() {
        Collection<BitVector> nonces = nonceService.getNonces().getData();
        return Lists.newArrayList(nonces);
    }

    @Override
    public void addNonces(List<BitVector> nonces) {
        nonceService.addNonces(nonces);
    }

    public BitVector generateNonce() {
        return BitUtils.randomVector(NONCE_LENGTH);
    }

}
