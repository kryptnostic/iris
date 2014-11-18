package com.kryptnostic.api.v1.security.loaders.rsa;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;

public final class FreshRsaKeyLoader extends RsaKeyLoader {
    
    @Override
    protected KeyPair tryLoading() throws KodexException {
        KeyPair keyPair;
        try {
            keyPair = Keys.generateRsaKeyPair( KEY_SIZE );

            return keyPair;
        } catch ( NoSuchAlgorithmException e ) {
            throw new KodexException( e );
        }
        // BlockCiphertext privateKeyCiphertext = crypto.encrypt( keyPair.getPrivate().getEncoded() );
    }

}
