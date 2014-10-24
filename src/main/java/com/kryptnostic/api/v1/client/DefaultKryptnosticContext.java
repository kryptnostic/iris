package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.models.FheEncryptable;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final SearchFunctionApi  searchFunctionClient;
    private final PrivateKey         privateKey;
    private final PublicKey          publicKey;
    private final SecurityService    securityService;

    private SimplePolynomialFunction globalHashFunction;

    private static final Logger      logger          = LoggerFactory.getLogger( DefaultKryptnosticContext.class );

    private static final int         TOKEN_LENGTH    = 256;
    private static final int         LOCATION_LENGTH = 64;
    private static final int         NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext( SearchFunctionApi searchFunctionClient, SecurityService securityService ) throws IrisException {
        this.searchFunctionClient = searchFunctionClient;
        this.securityService = securityService;

        SecurityConfigurationMapping mapping = this.securityService.getSecurityConfigurationMapping();

        if ( mapping == null ) {
            throw new IrisException(
                    "Security mapping was null and no keys could be found, the DefaultKryptnosticContext cannot be initialized without these keys" );
        }

        this.privateKey = mapping.get( FheEncryptable.class, PrivateKey.class );
        this.publicKey = mapping.get( FheEncryptable.class, PublicKey.class );
        this.globalHashFunction = null;

    }
    
    /**
     * TODO need to decrypt cipher nonces for local use
     */
    @Override
    public List<EncryptedSearchDocumentKey> getDocumentKeys() {
        throw new UnsupportedOperationException( "not yet implemented" );
        // Collection<EncryptedSearchDocumentKey> keys = documentKeyService.getDocumentKeys().getData();
        // return Lists.newArrayList( keys );
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

    @Override
    public SecurityService getSecurityService() {
        return this.securityService;
    }

    @Override
    public BitVector generateDocumentNonce() {
        return BitVectors.randomVector( NONCE_LENGTH );
    }

    @Override
    public SimplePolynomialFunction getGlobalHashFunction() throws ResourceNotFoundException {
        if ( globalHashFunction == null ) {
            globalHashFunction = this.searchFunctionClient.getFunction().getData();
        }
        return globalHashFunction;
    }
}
