package com.kryptnostic.api.v1.client;

import java.io.File;
import java.io.IOException;
import java.util.Map;

import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.storage.DataStore;

public class InMemoryStore implements DataStore {
    private final Map<String, byte[]> store = Maps.newConcurrentMap();

    @Override
    public byte[] get( String dir, String file ) throws IOException {
        return store.get( dir + File.pathSeparator + file );
    }

    @Override
    public void put( String dir, String file, byte[] value ) throws IOException {
        store.put( dir + File.pathSeparator + file, value );
    }

    @Override
    public byte[] get( String file ) throws IOException {
        return store.get( file );
    }

    @Override
    public void put( String file, byte[] value ) throws IOException {
        store.put( file, value );
    }

}
