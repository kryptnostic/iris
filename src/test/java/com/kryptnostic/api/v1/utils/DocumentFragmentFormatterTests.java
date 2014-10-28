package com.kryptnostic.api.v1.utils;

import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Test;

public class DocumentFragmentFormatterTests {
    @Test
    public void testTokenBeginning() {
        Assert.assertEquals(
                "this word is",
                DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 2 ) );
        Assert.assertEquals(
                "this word",
                DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 1 ) );
        Assert.assertEquals( "this", DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 0 ) );
        Assert.assertEquals(
                "this word is really",
                DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 3 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 4 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), 5 ) );
    }

    @Test
    public void testTokenMiddle() {
        Assert.assertEquals( "is", DocumentFragmentFormatter.format( makeEntry( 10, "this word is really cool" ), 0 ) );
        Assert.assertEquals(
                "word is really",
                DocumentFragmentFormatter.format( makeEntry( 10, "this word is really cool" ), 1 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 10, "this word is really cool" ), 2 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 10, "this word is really cool" ), 3 ) );
    }

    @Test
    public void testTokenEnd() {
        Assert.assertEquals( "cool", DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 0 ) );
        Assert.assertEquals(
                "really cool",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 1 ) );
        Assert.assertEquals(
                "is really cool",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 2 ) );
        Assert.assertEquals(
                "word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 3 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 4 ) );
        Assert.assertEquals(
                "this word is really cool",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really cool" ), 5 ) );
    }

    @Test(
        expected = IllegalArgumentException.class )
    public void testNegativeOffset() {
        DocumentFragmentFormatter.format( makeEntry( -1, "this word is really cool" ), 0 );
    }

    @Test(
        expected = IllegalArgumentException.class )
    public void testLongOffset() {
        DocumentFragmentFormatter.format( makeEntry( 2, "a" ), 0 );
    }

    @Test(
        expected = IllegalArgumentException.class )
    public void testInvalidWordWindow() {
        DocumentFragmentFormatter.format( makeEntry( 0, "this word is really cool" ), -1 );
    }

    private Entry<Integer, String> makeEntry( int i, String s ) {
        return Pair.<Integer, String> of( i, s );
    }
}
