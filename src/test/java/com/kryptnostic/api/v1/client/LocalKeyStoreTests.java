package com.kryptnostic.api.v1.client;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Test;

import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

public class LocalKeyStoreTests {
    private final PrivateKey fhePriv = new PrivateKey(128, 64);
    private final LocalKeyStore keyStore = new LocalKeyStore(
            ( new KodexObjectMapperFactory() ).getObjectMapper(null));

    @Test
    public void testStoreConfiguration() throws IOException {
        keyStore.storeFhePrivateKey(fhePriv);
    }

    @Test
    public void testStoreRetrieveConfiguration() throws IOException {
        keyStore.storeFhePrivateKey(fhePriv);
        PrivateKey retrieved = keyStore.retrieveFhePrivateKey();
        Assert.assertEquals(fhePriv, retrieved);
    }

}
