package com.kryptnostic.api.v1.security.loaders.rsa;

import java.security.KeyPair;

import com.kryptnostic.api.v1.security.loaders.Loader;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;

public abstract class RsaKeyLoader extends Loader<KeyPair> {
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
