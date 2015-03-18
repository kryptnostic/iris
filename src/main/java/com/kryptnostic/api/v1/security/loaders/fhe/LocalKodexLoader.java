package com.kryptnostic.api.v1.security.loaders.fhe;

import java.io.IOException;
import java.security.KeyPair;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.storage.DataStore;

public final class LocalKodexLoader extends KodexLoader {
    private static final Logger logger = LoggerFactory.getLogger( LocalKodexLoader.class );

    private final DataStore     dataStore;
    private final KeyPair       keyPair;

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
            Stopwatch watch = Stopwatch.createStarted();
            byte[] kodexBytes = Preconditions.checkNotNull(
                    dataStore.get( Kodex.class.getCanonicalName() ),
                    "Unable to loaded kodex from data store." );
            logger.debug( "[PROFILE] Took {} ms to load Kodex from disk", watch.elapsed( TimeUnit.MILLISECONDS ) );

            watch.reset().start();
            Kodex<String> kodex = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );
            kodex.unseal( keyPair.getPublic(), keyPair.getPrivate() );
            logger.debug( "[PROFILE] Took {} ms to load read and unseal kodex", watch.elapsed( TimeUnit.MILLISECONDS ) );

            return kodex;
        } catch (
                IOException
                | KodexException
                | SecurityConfigurationException
                | CorruptKodexException
                | NullPointerException e ) {
            throw new KodexException( e );
        }
    }
}
