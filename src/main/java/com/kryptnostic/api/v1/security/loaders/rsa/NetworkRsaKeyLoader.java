package com.kryptnostic.api.v1.security.loaders.rsa;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.directory.v1.models.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.PublicKeyAlgorithm;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;

public final class NetworkRsaKeyLoader extends RsaKeyLoader {
    private final PasswordCryptoService crypto;
    private final DirectoryApi          keyClient;
    private final UserKey               userKey;

    public NetworkRsaKeyLoader( PasswordCryptoService crypto, DirectoryApi keyClient, UserKey userKey ) throws KodexException {
        if ( crypto == null || keyClient == null || userKey == null ) {
            throw new KodexException( "null values" );
        }
        this.crypto = crypto;
        this.keyClient = keyClient;
        this.userKey = userKey;
    }

    @Override
    protected KeyPair tryLoading() throws KodexException {
        BlockCiphertext rsaPrivateKeyCiphertext = keyClient.getPrivateKey();
        PublicKeyEnvelope envelope = keyClient.getPublicKey( userKey.getName() );
        if ( rsaPrivateKeyCiphertext == null || envelope == null ) {
            throw new KodexException( "Encryption keys could not be retrieved from the network" );
        }

        try {
            byte[] decryptedPrivateKeyBytes = crypto.decryptBytes( rsaPrivateKeyCiphertext );
            byte[] decryptedPublicKeyBytes = envelope.getBytes();

            PrivateKey rsaPrivateKey = Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPrivateKeyBytes );
            PublicKey rsaPublicKey = Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, decryptedPublicKeyBytes );

            return new KeyPair( rsaPublicKey, rsaPrivateKey );

        } catch ( SecurityConfigurationException | InvalidKeySpecException | NoSuchAlgorithmException e ) {
            throw new KodexException( e );
        }
    }
}
