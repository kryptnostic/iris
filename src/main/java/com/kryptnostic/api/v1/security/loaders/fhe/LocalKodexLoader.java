package com.kryptnostic.api.v1.security.loaders.fhe;

import java.io.IOException;
import java.security.KeyPair;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.base.Preconditions;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.storage.DataStore;

public final class LocalKodexLoader extends KodexLoader {
    private final DataStore dataStore;
    private final KeyPair   keyPair;

    public LocalKodexLoader( KeyPair keyPair, DataStore dataStore ) {
        Preconditions.checkNotNull( dataStore );
        Preconditions.checkNotNull( keyPair );
        this.dataStore = dataStore;
        this.keyPair = keyPair;
    }

    /**
     * Attempt to laod Kodex via a DataStore
     */
    @Override
    public Kodex<String> tryLoading() throws KodexException {
        try {

            byte[] kodexBytes = dataStore.get( Kodex.class.getCanonicalName().getBytes() );

            Kodex<String> kodex = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );

            kodex.unseal( keyPair.getPrivate() );

            return kodex;
        } catch ( IOException | KodexException | SecurityConfigurationException | CorruptKodexException e ) {
            throw new KodexException( e );
        }
    }
}
