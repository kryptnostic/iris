package com.kryptnostic.utils;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;

import com.kryptnostic.kodex.v1.storage.DataStore;

/**
 * Abstract class to test implementations of {@link DataStore} contract.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public abstract class DataStoreTestsBase {
    protected static DataStore         store;
    private static final AtomicInteger counter          = new AtomicInteger();

    @Test
    public void testPut() throws IOException {
        byte[] data = getRandomData();
        Pair<String, String> p = getKey( data );
        store.put( p.getLeft(), p.getRight(), data );
    }

    private Pair<String, String> getKey( byte[] data ) {
        return Pair.<String, String> of( "dir", StringUtils.newStringUtf8( data ) );
    }

    @Test
    public void testPutGet() throws IOException {
        byte[] data = getRandomData();
        Pair<String, String> p = getKey( data );
        store.put( p.getLeft(), p.getRight(), data );

        byte[] retrieved = store.get( p.getLeft(), p.getRight() );
        Assert.assertTrue( Arrays.equals( data, retrieved ) );
    }

    @Test
    public void testGetNull() throws IOException {
        Pair<String, String> p = getKey( getRandomData() );
        byte[] retrieved = store.get( p.getLeft(), p.getRight() );
        Assert.assertNull( retrieved );
    }

    @Test
    public void testPutOverwrite() throws IOException {
        byte[] data0 = getRandomData();
        byte[] data1 = getRandomData();
        Pair<String, String> p = getKey( data0 );
        store.put( p.getLeft(), p.getRight(), data0 );
        byte[] retrieved0 = store.get( p.getLeft(), p.getRight() );
        Assert.assertTrue( Arrays.equals( data0, retrieved0 ) );
        store.put( p.getLeft(), p.getRight(), data1 );
        byte[] retrieved1 = store.get( p.getLeft(), p.getRight() );
        Assert.assertTrue( Arrays.equals( data1, retrieved1 ) );
    }

    @Test
    public void testDirectory() throws IOException {
        store.put( "dir", "cool", "test".getBytes() );
        Assert.assertEquals( "test", StringUtils.newStringUtf8( store.get( "dir", "cool" ) ) );
        Assert.assertNull( store.get( "dir" + File.pathSeparator + "cool" ) );
    }

    @Test
    public void testDelete() throws IOException {
        store.put( "test123", "test".getBytes() );
        store.delete( "test123" );
        Assert.assertNull( store.get( "test123" ) );
    }

    private byte[] getRandomData() {
        return ( "test" + String.valueOf( counter.getAndIncrement() ) ).getBytes();
    }
}
