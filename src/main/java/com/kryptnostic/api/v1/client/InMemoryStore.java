package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.util.Map;

import org.apache.commons.codec.binary.Hex;

import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.storage.DataStore;

public class InMemoryStore implements DataStore {
    private final Map<String, byte[]> store = Maps.newConcurrentMap();

    @Override
    public byte[] get( byte[] key ) throws IOException {
        return store.get( Hex.encodeHexString( key ) );
    }

    @Override
    public void put( byte[] key, byte[] value ) throws IOException {
        store.put( Hex.encodeHexString( key ), value );
    }

}
