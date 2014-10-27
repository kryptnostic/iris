package com.kryptnostic.api.v1.security.loaders;

import com.google.common.base.Preconditions;
import com.kryptnostic.api.v1.security.KodexLoader;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.users.v1.UserKey;

public class NetworkKodexLoader extends KodexLoader {
    private final KeyApi        keyClient;
    private final UserKey       userKey;
    private final CryptoService crypto;

    public NetworkKodexLoader( KeyApi keyClient, UserKey userKey, CryptoService crypto ) {
        Preconditions.checkNotNull( keyClient );
        Preconditions.checkNotNull( userKey );
        Preconditions.checkNotNull( crypto );
        this.keyClient = keyClient;
        this.userKey = userKey;
        this.crypto = crypto;
    }

    /**
     * Attempt to load a Kodex via network
     */
    @Override
    public Kodex<String> tryLoadingKodex() throws KodexException {
        try {
            byte[] privateKey = crypto.decryptBytes( keyClient.getPrivateKey() );
            byte[] publicKeyBytes = keyClient.getPublicKey( userKey.getRealm(), userKey.getName() ).getBytes();
            byte[] kodexBytes = keyClient.getKodex().getEncryptedKey();

            return unsealAndVerifyKodex( privateKey, publicKeyBytes, kodexBytes );
        } catch ( SecurityConfigurationException | IrisException e ) {
            throw new KodexException( e );
        }

    }
}
