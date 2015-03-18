package com.kryptnostic.api.v1.security.loaders.fhe;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Preconditions;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;

public final class NetworkKodexLoader extends KodexLoader {
    private static final Logger logger = LoggerFactory.getLogger( NetworkKodexLoader.class );
    private final KeyPair       keyPair;
    private final DirectoryApi  keyClient;

    public NetworkKodexLoader( KeyPair keyPair, DirectoryApi keyClient ) {
        Preconditions.checkNotNull( keyPair );
        Preconditions.checkNotNull( keyClient );
        this.keyClient = keyClient;
        this.keyPair = keyPair;
    }

    /**
     * Attempt to load a Kodex via network
     */
    @Override
    public Kodex<String> tryLoading() throws KodexException {
        try {
            Kodex<String> kodex = null;
            try {
                kodex = keyClient.getKodex();
            } catch ( ResourceNotFoundException e ) {
                if ( e.getMessage() != null ) {
                    logger.debug( e.getMessage() );
                }
            }

            if ( kodex == null ) {
                throw new KodexException( "Kodex could not be found on the network" );
            }

            kodex.verify( keyPair.getPublic() );
            kodex.unseal( keyPair.getPublic(), keyPair.getPrivate() );

            return kodex;
        } catch (
                InvalidKeyException
                | SignatureException
                | JsonProcessingException
                | CorruptKodexException
                | SecurityConfigurationException e ) {
            throw new KodexException( e );
        }

    }
}
