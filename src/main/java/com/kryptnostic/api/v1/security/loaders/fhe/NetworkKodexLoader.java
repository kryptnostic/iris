package com.kryptnostic.api.v1.security.loaders.fhe;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.SignatureException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Preconditions;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;

public final class NetworkKodexLoader extends KodexLoader {
    private final KeyPair keyPair;
    private final KeyApi  keyClient;

    public NetworkKodexLoader( KeyPair keyPair, KeyApi keyClient ) {
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
            Kodex<String> kodex = keyClient.getKodex();

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
