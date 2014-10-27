package com.kryptnostic.api.v1.security.loaders;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.google.common.base.Preconditions;
import com.kryptnostic.api.v1.security.KodexLoader;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.storage.DataStore;

public class LocalKodexLoader extends KodexLoader {
    private final DataStore     dataStore;
    private final CryptoService crypto;

    public LocalKodexLoader( DataStore dataStore, CryptoService crypto ) {
        Preconditions.checkNotNull( dataStore );
        Preconditions.checkNotNull( crypto );
        this.dataStore = dataStore;
        this.crypto = crypto;
    }

    /**
     * Attempt to laod Kodex via a DataStore
     */
    @Override
    public Kodex<String> tryLoadingKodex() throws KodexException {
        try {
            byte[] encryptedPrivateKeyBytes = dataStore.get( PrivateKey.class.getCanonicalName().getBytes() );
            BlockCiphertext privateKeyCiphertext = mapper.readValue( encryptedPrivateKeyBytes, BlockCiphertext.class );
            byte[] privateKey = crypto.decryptBytes( privateKeyCiphertext );

            byte[] decryptedPublicKeyBytes = dataStore.get( PublicKey.class.getCanonicalName().getBytes() );
            byte[] kodexBytes = dataStore.get( Kodex.class.getCanonicalName().getBytes() );

            return unsealAndVerifyKodex( privateKey, decryptedPublicKeyBytes, kodexBytes );
        } catch ( IOException | KodexException | SecurityConfigurationException | IrisException e ) {
            throw new KodexException( e );
        }
    }
}
