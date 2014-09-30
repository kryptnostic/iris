package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.linear.BitUtils;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.search.v1.models.request.SearchFunctionUploadRequest;
import com.kryptnostic.storage.v1.client.NonceApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final NonceApi nonceService;
    private final SearchFunctionApi searchFunctionService;
    private final PrivateKey privateKey = new PrivateKey(CIPHER_BLOCK_LENGTH, PLAINTEXT_BLOCK_LENGTH);
    private final PublicKey publicKey = new PublicKey(privateKey);
    private final SecurityService securityService;

    private SimplePolynomialFunction indexingHashFunction;

    private static final Logger logger = LoggerFactory.getLogger(DefaultKryptnosticContext.class);

    private static final int TOKEN_LENGTH = 256;
    private static final int LOCATION_LENGTH = 64;
    private static final int NONCE_LENGTH = 64;
    private static final int CIPHER_BLOCK_LENGTH = 128;
    private static final int PLAINTEXT_BLOCK_LENGTH = 64;

    public DefaultKryptnosticContext(SearchFunctionApi searchFunctionService, NonceApi nonceService,
            SecurityService securityService) {
        this.searchFunctionService = searchFunctionService;
        this.nonceService = nonceService;
        this.securityService = securityService;
    }

    /** 
     * Gets a search function locally, or, if one does not exist, generates a search function and
     * persists the homomorphism to the search service.
     */
    @Override
    public SimplePolynomialFunction getSearchFunction() {
        if (indexingHashFunction == null) {
            try {
                indexingHashFunction = searchFunctionService.getFunction().getData(); 
            } catch (Exception e) {
                
            }
            if (indexingHashFunction == null) {
                logger.info("Generating search function.");
                indexingHashFunction = Indexes.generateRandomIndexingFunction(NONCE_LENGTH, TOKEN_LENGTH,
                        LOCATION_LENGTH);

                setFunction(indexingHashFunction);
            }
        }
        return indexingHashFunction;
    }

    /**
     * Wraps call to SearchFunctionService, first encrypting the function with FHE before sending it.
     * TODO make this async or something...hide latency of compose
     */
    private void setFunction(SimplePolynomialFunction indexingHashFunction) {
        SimplePolynomialFunction indexingHomomorphism = indexingHashFunction.partialComposeLeft(privateKey
                .getDecryptor());
        SearchFunctionUploadRequest request = new SearchFunctionUploadRequest(indexingHomomorphism);
        searchFunctionService.setFunction(request);
    }

    /**
     * TODO need to decrypt cipher nonces for local use
     */
    @Override
    public List<BitVector> getNonces() {
        Collection<BitVector> nonces = nonceService.getNonces().getData();
        return Lists.newArrayList(nonces);
    }

    /**
     * Sends the nonce service cipher nonces, for use with the search homomorphism.
     */
    @Override
    public void addNonces(List<BitVector> nonces) {
        List<BitVector> cipherNonces = Lists.newArrayList();
        for (BitVector nonce : nonces) {
            SimplePolynomialFunction encrypter = publicKey.getEncrypter();
            BitVector cipherNonce = encrypter.apply(nonce, BitUtils.randomVector(nonce.size()));
            cipherNonces.add(cipherNonce);
        }
        nonceService.addNonces(cipherNonces);
    }

    public BitVector generateNonce() {
        return BitUtils.randomVector(NONCE_LENGTH);
    }

    @Override
    public SecurityService getSecurityService() {
        return this.securityService;
    }

}
