package com.kryptnostic.api.v1.security.loaders.rsa;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;

public final class LocalRsaKeyLoader extends RsaKeyLoader {
    private final ObjectMapper  mapper = KodexObjectMapperFactory.getObjectMapper();
    private final CryptoService crypto;
    private final DataStore     dataStore;

    public LocalRsaKeyLoader( CryptoService crypto, DataStore dataStore ) throws KodexException {
        if ( crypto == null || dataStore == null ) {
            throw new KodexException( "Crypto service and data store are required to load from disk" );
        }
        this.crypto = crypto;
        this.dataStore = dataStore;
    }

    @Override
    protected KeyPair tryLoading() throws KodexException {
        try {
            byte[] encryptedPrivateKeyBytes = dataStore.get( PrivateKey.class.getCanonicalName().getBytes() );
            BlockCiphertext privateKeyCiphertext = mapper.readValue( encryptedPrivateKeyBytes, BlockCiphertext.class );
            byte[] decryptedPrivateKeyBytes = crypto.decryptBytes( privateKeyCiphertext );

            byte[] decryptedPublicKeyBytes = dataStore.get( PublicKey.class.getCanonicalName().getBytes() );

            PrivateKey rsaPrivateKey = Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPrivateKeyBytes );
            PublicKey rsaPublicKey = Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPublicKeyBytes );

            return new KeyPair( rsaPublicKey, rsaPrivateKey );
        } catch ( InvalidKeySpecException | NoSuchAlgorithmException | SecurityConfigurationException | IOException e ) {
            throw new KodexException( e );
        }

    }

}
