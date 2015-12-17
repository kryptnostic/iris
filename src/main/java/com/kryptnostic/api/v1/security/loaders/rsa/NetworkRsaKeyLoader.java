package com.kryptnostic.api.v1.security.loaders.rsa;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.v2.storage.api.KeyStorageApi;

public final class NetworkRsaKeyLoader extends RsaKeyLoader {
    private static final Logger         logger = LoggerFactory.getLogger( NetworkRsaKeyLoader.class );
    private final PasswordCryptoService crypto;
    private final KeyStorageApi         keyApi;
    private final UUID                  userKey;

    public NetworkRsaKeyLoader( PasswordCryptoService crypto, KeyStorageApi keyApi, UUID userKey ) throws KodexException {
        if ( crypto == null || keyApi == null || userKey == null ) {
            throw new KodexException( "null values" );
        }
        this.crypto = crypto;
        this.keyApi = keyApi;
        this.userKey = userKey;
    }

    @Override
    protected KeyPair tryLoading() throws KodexException {
        BlockCiphertext rsaPrivateKeyCiphertext = null;
        byte[] pubKey = null;
        rsaPrivateKeyCiphertext = keyApi.getRSAPrivateKey();
        pubKey = keyApi.getRSAPublicKey( userKey );
        if ( rsaPrivateKeyCiphertext == null || pubKey == null ) {
            throw new KodexException( "Encryption keys could not be retrieved from the network" );
        }

        try {
            byte[] decryptedPrivateKeyBytes = crypto.decryptBytes( rsaPrivateKeyCiphertext );
            byte[] publicKeyBytes = pubKey;

            PrivateKey rsaPrivateKey = Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPrivateKeyBytes );
            PublicKey rsaPublicKey = Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, publicKeyBytes );

            return new KeyPair( rsaPublicKey, rsaPrivateKey );

        } catch ( SecurityConfigurationException | InvalidKeySpecException | NoSuchAlgorithmException e ) {
            throw new KodexException( e );
        }
    }
}
