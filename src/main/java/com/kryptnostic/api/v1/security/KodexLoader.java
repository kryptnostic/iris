package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.crypto.v1.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

/**
 * Provider of immutable {@link KeyPackage} to encapsulate logic of retrieving consistent keys.
 * 
 * @author sinaiman
 *
 */
public abstract class KodexLoader {

    private static final Logger  logger       = LoggerFactory.getLogger( KodexLoader.class );

    public static final String   LEFT_HASHER  = "LEFT";
    public static final String   RIGHT_HASHER = "LEFT";

    protected PrivateKey         rsaPriv;
    protected PublicKey          rsaPub;
    protected final ObjectMapper mapper       = KodexObjectMapperFactory.getObjectMapper();

    public KodexLoader() {}

    /**
     * Helper method to correctly verify and unseal a Kodex
     * 
     * @param privateKey
     * @param publicKey
     * @param kodexBytes
     * @return
     * @throws IrisException
     * @throws KodexException
     */
    protected final Kodex<String> unsealAndVerifyKodex( byte[] privateKey, byte[] publicKey, byte[] kodexBytes )
            throws IrisException, KodexException {

        try {
            rsaPriv = Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, privateKey );
            rsaPub = Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, publicKey );

            Kodex<String> kodex = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );

            kodex.unseal( rsaPriv );

            return kodex;

        } catch ( InvalidKeySpecException | IOException | NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        } catch ( KodexException | SecurityConfigurationException | CorruptKodexException e ) {
            throw new KodexException( e );
        }
    }

    /**
     * Enforces validity of the returned Kodex
     * 
     * A Kodex will not be returned unless it is considered valid
     * 
     * @return The valid Kodex, returned UNSEALED. Dirty only if it was freshly created or any keys were modified in the
     *         loading process
     * @throws IrisException If the Kodex candidate was determined to be invalid
     */
    public final Kodex<String> loadKodex() throws KodexException {
        Kodex<String> candidate;
        candidate = tryLoadingKodex();
        if ( validateKodex( candidate ) ) {
            return candidate;
        } else {
            throw new KodexException(
                    "Loaded Kodex, but it was missing keys. Aborting Kodex load due to this validation error. Make sure your keys can be read from disk and your network is connected." );
        }
    }

    protected abstract Kodex<String> tryLoadingKodex() throws KodexException;

    /**
     * Determines whether a specific Kodex is valid or not
     * 
     * @param kodex
     * @return
     * @throws IrisException
     * @throws SealedKodexException
     */
    private static final boolean validateKodex( Kodex<String> kodex ) throws KodexException {
        try {
            return kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) != null
                    && kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) != null
                    && kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) != null
                    && kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                            + KodexLoader.LEFT_HASHER, SimplePolynomialFunction.class ) != null
                    && kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                            + KodexLoader.RIGHT_HASHER, SimplePolynomialFunction.class ) != null;
        } catch ( SecurityConfigurationException | SealedKodexException e ) {
            throw new KodexException( e );
        }
    }

}
