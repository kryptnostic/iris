package com.kryptnostic.api.v1.security;

import java.math.BigInteger;
import java.security.SecureRandom;

import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.kodex.v1.models.AesEncryptable;
import com.kryptnostic.kodex.v1.models.FheEncryptable;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.users.v1.UserKey;

public class InMemorySecurityService implements SecurityService {

    private SecurityConfigurationMapping mapping;

    private final UserKey                userKey;
    private final String                 userCredential;

    public InMemorySecurityService( UserKey userKey, String userCredential ) {
        com.kryptnostic.crypto.PrivateKey fhePrv = new com.kryptnostic.crypto.PrivateKey( 128, 64 );
        com.kryptnostic.crypto.PublicKey fhePub = new com.kryptnostic.crypto.PublicKey( fhePrv );

        CryptoService cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, new BigInteger(
                130,
                new SecureRandom() ).toString( 32 ).toCharArray() );

        this.mapping = new SecurityConfigurationMapping().add( FheEncryptable.class, fhePub )
                .add( FheEncryptable.class, fhePrv ).add( AesEncryptable.class, cryptoService );

        this.userCredential = userCredential;
        this.userKey = userKey;
    }

    @Override
    public SecurityConfigurationMapping getSecurityConfigurationMapping() {
        return this.mapping;
    }

    @Override
    public String getUserCredential() {
        return userCredential;
    }

    @Override
    public UserKey getUserKey() {
        return userKey;
    }
}
