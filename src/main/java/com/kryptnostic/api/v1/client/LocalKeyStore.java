package com.kryptnostic.api.v1.client;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.kodex.v1.storage.DataStore;

/**
 * Class to support storing private keys on device.
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class LocalKeyStore {
    private final DataStore store;
    private final ObjectMapper mapper;

    public LocalKeyStore(ObjectMapper mapper) {
        this.store = new FileStore("keys");
        this.mapper = mapper;
    }
    
    public void storeFhePrivateKey(PrivateKey fheKey) throws IOException {
        storeValue(PrivateKey.class.getCanonicalName(), fheKey);
    }
    
    public PrivateKey retrieveFhePrivateKey() throws IOException {
        return retrieveValue(PrivateKey.class.getCanonicalName(), PrivateKey.class);    
    }

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
