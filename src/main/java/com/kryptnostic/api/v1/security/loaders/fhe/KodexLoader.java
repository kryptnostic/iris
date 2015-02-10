package com.kryptnostic.api.v1.security.loaders.fhe;

import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Stopwatch;
import com.kryptnostic.api.v1.security.loaders.Loader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public abstract class KodexLoader extends Loader<Kodex<String>> {

    private static final Logger  logger          = LoggerFactory.getLogger( KodexLoader.class );

    public static final String   LEFT_HASHER     = "LEFT";
    public static final String   RIGHT_HASHER    = "RIGHT";

    public static final byte[]   LEFT_VALIDATOR  = "LEFT_VALIDATOR".getBytes();
    public static final byte[]   RIGHT_VALIDATOR = "RIGHT_VALIDATOR".getBytes();

    protected final ObjectMapper mapper          = KodexObjectMapperFactory.getObjectMapper();

    public KodexLoader() {}

    /**
     * Enforces validity of the returned Kodex
     * 
     * A Kodex will not be returned unless it is considered valid
     * 
     * @return The valid Kodex, returned UNSEALED. Dirty only if it was freshly created or any keys were modified in the
     *         loading process
     * @throws KodexException If the Kodex candidate was determined to be invalid
     */
    @Override
    public final Kodex<String> load() throws KodexException {
        Kodex<String> candidate;
        candidate = tryLoading();
        if ( validate( candidate ) ) {
            return candidate;
        } else {
            throw new KodexException(
                    "Loaded Kodex, but it was missing keys. Aborting Kodex load due to this validation error. Make sure your keys can be read from disk and your network is connected." );
        }
    }

    @Override
    protected abstract Kodex<String> tryLoading() throws KodexException;

    /**
     * Determines whether a specific Kodex is valid or not
     * 
     * @param kodex
     * @return
     * @throws KodexException
     */
    @Override
    protected final boolean validate( Kodex<String> kodex ) throws KodexException {
        try {
            Stopwatch watch2 = Stopwatch.createStarted();
            com.kryptnostic.crypto.PrivateKey privKey = kodex
                    .getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            logger.debug( "[PROFILE] Load PrivateKey from Kodex {} ms", watch2.elapsed( TimeUnit.MILLISECONDS ) );
            watch2.reset().start();
            com.kryptnostic.crypto.PublicKey pubKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            logger.debug( "[PROFILE] Load PublicKey from Kodex {} ms", watch2.elapsed( TimeUnit.MILLISECONDS ) );
            watch2.reset().start();
            EncryptedSearchPrivateKey espk = kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
            logger.debug(
                    "[PROFILE] Load EncryptedSearchPrivateKey from Kodex {} ms",
                    watch2.elapsed( TimeUnit.MILLISECONDS ) );
            watch2.reset().start();
            String qhp = kodex.getKeyWithJackson( QueryHasherPairRequest.class.getCanonicalName(), String.class );
            logger.debug(
                    "[PROFILE] Load QueryHasherPairRequest from Kodex {} ms",
                    watch2.elapsed( TimeUnit.MILLISECONDS ) );
            boolean valid = privKey != null && pubKey != null && espk != null && qhp != null;
            return valid;
        } catch ( SecurityConfigurationException | SealedKodexException e ) {
            throw new KodexException( e );
        }
    }

}
