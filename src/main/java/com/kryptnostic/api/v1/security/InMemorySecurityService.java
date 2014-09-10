package com.kryptnostic.api.v1.security;

import com.kryptnostic.kodex.v1.models.FheEncryptable;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.kodex.v1.security.SecurityService;

public class InMemorySecurityService implements SecurityService {

    private SecurityConfigurationMapping mapping;

    public InMemorySecurityService() {
        com.kryptnostic.crypto.PrivateKey fhePrv = new com.kryptnostic.crypto.PrivateKey(128, 64);
        com.kryptnostic.crypto.PublicKey fhePub = new com.kryptnostic.crypto.PublicKey(fhePrv);

        java.security.PublicKey aesPub = null;
        java.security.PrivateKey aesPrv = null;

        this.mapping = new SecurityConfigurationMapping().add(FheEncryptable.class, fhePub, fhePrv);
        // .add(EncryptionScheme.AES, aesPub, aesPrv);
    }

    @Override
    public SecurityConfigurationMapping getSecurityConfigurationMapping() {
        return this.mapping;
    }

}
