package com.kryptnostic.api.v1.client;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.kodex.v1.models.FheEncryptable;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.kodex.v1.storage.DataStore;

public class SecurityConfigurationStore {
    private final DataStore store;
    private final ObjectMapper mapper;

    public SecurityConfigurationStore(ObjectMapper mapper) {
        this.store = new FileStore("keys");
        this.mapper = mapper;
    }

    // TODO serialize each key into a byte array and store it
    public void storeKeys(SecurityConfigurationMapping mapping) throws IOException {
        // extract each key class and store it
        PublicKey pubKey = mapping.get(FheEncryptable.class, PublicKey.class);
        storeValue(pubKey.getClass().getCanonicalName(), pubKey);
    }
    
    public SecurityConfigurationMapping getMapping() throws IOException {
        PublicKey pubKey = retrieveValue(PublicKey.class.getCanonicalName(), PublicKey.class);
        return null;
    }

    /**
     * Serialize object to byte array with Jackson and store it in DataStore.
     */
    private void storeValue(String keyString, Object value) throws IOException {
        byte[] data = mapper.writeValueAsBytes(value);
        byte[] key = keyString.getBytes();
        store.put(key, data);
    }
    
    private <T>T retrieveValue(String keyString, Class<T> clazz) throws IOException {
        byte[] data = store.get(keyString.getBytes());
        return mapper.readValue(data, clazz);
    }

    
}
