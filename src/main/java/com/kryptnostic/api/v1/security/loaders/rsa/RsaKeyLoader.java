package com.kryptnostic.api.v1.security.loaders.rsa;

import java.security.KeyPair;

import com.kryptnostic.api.v1.security.loaders.Loader;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;

public abstract class RsaKeyLoader extends Loader<KeyPair> {
    public static final int KEY_SIZE = 4096;
    public static final Cypher CIPHER = Cypher.RSA_OAEP_SHA256_4096;
    public static final PublicKeyAlgorithm ALGORITHM = PublicKeyAlgorithm.RSA;
    
    @Override
    protected abstract KeyPair tryLoading() throws KodexException;

    @Override
    protected final boolean validate( KeyPair keys ) throws KodexException {

        return true;
    }

    @Override
    public final KeyPair load() throws KodexException {
        KeyPair candidate;
        candidate = tryLoading();
        if ( validate( candidate ) ) {
            return candidate;
        } else {
            throw new KodexException( "Loaded Keys, but they were invalid" );
        }
    }
}
