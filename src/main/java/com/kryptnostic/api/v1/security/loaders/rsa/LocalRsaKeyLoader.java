package com.kryptnostic.api.v1.security.loaders.rsa;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;

public final class LocalRsaKeyLoader extends RsaKeyLoader {
    private final ObjectMapper  mapper = KodexObjectMapperFactory.getObjectMapper();
    private final CryptoService crypto;
    private final DataStore     dataStore;
    private final DirectoryApi  keyClient;

    public LocalRsaKeyLoader( CryptoService crypto, DirectoryApi keyClient, DataStore dataStore ) throws KodexException {
        if ( crypto == null || dataStore == null || keyClient == null ) {
            throw new KodexException(
                    "Crypto service, key network client, and data store are required to load from disk" );
        }
        this.keyClient = keyClient;
        this.crypto = crypto;
        this.dataStore = dataStore;
    }

    @Override
    protected KeyPair tryLoading() throws KodexException {
        try {
            byte[] encryptedPrivateKeyBytes = Preconditions.checkNotNull(
                    dataStore.get( PrivateKey.class.getCanonicalName().getBytes() ),
                    "Couldn't load private key from data store." );
            BlockCiphertext privateKeyCiphertext = mapper.readValue( encryptedPrivateKeyBytes, BlockCiphertext.class );

            // need to check if local privateKey is synced with the server and user is authenticated

            BlockCiphertext networkPrivateKey = keyClient.getPrivateKey();
            if ( networkPrivateKey == null ) {
                throw new KodexException( "User not recognized" );
            }

            byte[] decryptedPrivateKeyBytes = crypto.decryptBytes( privateKeyCiphertext );

            byte[] decryptedPublicKeyBytes = Preconditions.checkNotNull(
                    dataStore.get( PublicKey.class.getCanonicalName().getBytes() ),
                    "Couldn't load public key from data store." );

            PrivateKey rsaPrivateKey = Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPrivateKeyBytes );
            PublicKey rsaPublicKey = Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPublicKeyBytes );

            return new KeyPair( rsaPublicKey, rsaPrivateKey );
        } catch (
                InvalidKeySpecException
                | NoSuchAlgorithmException
                | SecurityConfigurationException
                | IOException
                | NullPointerException e ) {
            throw new KodexException( e );
        }

    }

}
