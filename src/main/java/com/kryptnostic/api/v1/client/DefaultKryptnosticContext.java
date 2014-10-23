package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.models.FheEncryptable;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.search.v1.models.request.SearchFunctionUploadRequest;
import com.kryptnostic.storage.v1.client.DocumentKeyApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final DocumentKeyApi     documentKeyService;
    private final SearchFunctionApi  searchFunctionService;
    private final PrivateKey         privateKey;
    private final PublicKey          publicKey;
    private final SecurityService    securityService;

    private SimplePolynomialFunction indexingHashFunction;

    private static final Logger      logger          = LoggerFactory.getLogger( DefaultKryptnosticContext.class );

    private static final int         TOKEN_LENGTH    = 256;
    private static final int         LOCATION_LENGTH = 64;
    private static final int         NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext(
            SearchFunctionApi searchFunctionService,
            DocumentKeyApi documentKeyService,
            SecurityService securityService ) {
        this.searchFunctionService = searchFunctionService;
        this.documentKeyService = documentKeyService;
        this.securityService = securityService;

        SecurityConfigurationMapping mapping = this.securityService.getSecurityConfigurationMapping();

        if ( mapping != null ) {
            this.privateKey = mapping.get( FheEncryptable.class, PrivateKey.class );
            this.publicKey = mapping.get( FheEncryptable.class, PublicKey.class );
        } else {
            this.privateKey = null;
            this.publicKey = null;
        }
    }

    /**
     * Gets a search function locally, or, if one does not exist, generates a search function and persists the
     * homomorphism to the search service.
     */
    @Override
    public SimplePolynomialFunction getSearchFunction() {
        if ( indexingHashFunction == null ) {
            try {
                indexingHashFunction = searchFunctionService.getFunction().getData();
            } catch ( Exception e ) {

            }
            if ( indexingHashFunction == null ) {
                logger.info( "Generating search function." );
                indexingHashFunction = Indexes.generateRandomIndexingFunction(
                        NONCE_LENGTH,
                        TOKEN_LENGTH,
                        LOCATION_LENGTH );

                setFunction( indexingHashFunction );
            }
        }
        return indexingHashFunction;
    }

    /**
     * Wraps call to SearchFunctionService, first encrypting the function with FHE before sending it. TODO make this
     * async or something...hide latency of compose
     */
    private void setFunction( SimplePolynomialFunction indexingHashFunction ) {
        SimplePolynomialFunction indexingHomomorphism = indexingHashFunction.partialComposeLeft( privateKey
                .getDecryptor() );
        SearchFunctionUploadRequest request = new SearchFunctionUploadRequest( indexingHomomorphism );
        // searchFunctionService.setFunction(request);
        throw new UnsupportedOperationException( "not yet implemented" );
    }

    /**
     * TODO need to decrypt cipher nonces for local use
     */
    @Override
    public List<EncryptedSearchDocumentKey> getDocumentKeys() {
        Collection<EncryptedSearchDocumentKey> keys = documentKeyService.getDocumentKeys().getData();
        return Lists.newArrayList( keys );
    }

    /**
     * Sends the encryptedSearchDocumentKeys up to the server
     */
    @Override
    public void addDocumentKeys( List<EncryptedSearchDocumentKey> keys ) {
        // List<BitVector> cipherNonces = Lists.newArrayList();
        // for (EncryptedSearchDocumentKey key : keys) {
        // SimplePolynomialFunction encrypter = publicKey.getEncrypter();
        // BitVector cipherNonce = encrypter.apply(nonce, BitVectors.randomVector(nonce.size()));
        // cipherNonces.add(cipherNonce);
        // }
        // documentKeyService.addDocumentKeys(cipherNonces);
        throw new UnsupportedOperationException( "not yet implemented" );
    }

    public BitVector generateNonce() {
        return BitVectors.randomVector( NONCE_LENGTH );
    }

    @Override
    public SecurityService getSecurityService() {
        return this.securityService;
    }

    @Override
    public void setSearchFunction( SimplePolynomialFunction fn ) {
        indexingHashFunction = fn;
        setFunction( fn );
    }

}
