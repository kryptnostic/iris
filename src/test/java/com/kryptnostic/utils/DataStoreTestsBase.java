package com.kryptnostic.utils;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.kryptnostic.kodex.v1.storage.DataStore;

/**
 * Abstract class to test implementations of {@link DataStore} contract.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public abstract class DataStoreTestsBase {
    protected static DataStore  store;
    private static HashFunction hf               = Hashing.murmur3_128();
    private static final int    DATA_BYTE_LENGTH = 50;
    private static final Random r                = new Random();

    @Test
    public void testPut() throws IOException {
        byte[] data = getRandomData();
        byte[] key = getKey( data );
        store.put( key, data );
    }

    @Test
    public void testPutGet() throws IOException {
        byte[] data = getRandomData();
        byte[] key = getKey( data );
        store.put( key, data );

        byte[] retrieved = store.get( key );
        Assert.assertTrue( Arrays.equals( data, retrieved ) );
    }

    @Test
    public void testGetNull() throws IOException {
        byte[] wrongKey = getKey( getRandomData() );
        byte[] retrieved = store.get( wrongKey );
        Assert.assertNull( retrieved );
    }

    @Test
    public void testPutOverwrite() throws IOException {
        byte[] data0 = getRandomData();
        byte[] data1 = getRandomData();
        byte[] key = getKey( data0 );
        store.put( key, data0 );
        byte[] retrieved0 = store.get( key );
        Assert.assertTrue( Arrays.equals( data0, retrieved0 ) );
        store.put( key, data1 );
        byte[] retrieved1 = store.get( key );
        Assert.assertTrue( Arrays.equals( data1, retrieved1 ) );
    }

    private byte[] getKey( byte[] value ) {
        return hf.hashBytes( value ).asBytes();
    }

    private byte[] getRandomData() {
        byte[] data = new byte[ DATA_BYTE_LENGTH ];
        r.nextBytes( data );
        return data;
    }
}
