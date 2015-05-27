package com.kryptnostic.api.v1.utils;

import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Ignore;
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
    public void testChat() {
        String doc = "matt: blah\n" + "matt: yrdy\n" + "sina: test\n" + "sina: test\n" + "matt: yeah buddy\n"
                + "sina: yeah\n" + "sina: :)\n" + "matt: This is so sick\n" + "sina: yes\\n it is\n";
        int index = doc.indexOf( "yrdy" );
        Assert.assertEquals(
                "blah matt: yrdy sina: test",
                DocumentFragmentFormatter.format( makeEntry( index, doc ), 2 ) );
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

    @Test
    public void testNarrow() {
        Assert.assertEquals(
                "I am super cool and I dont care",
                DocumentFragmentFormatter.format( makeEntry( 11, "I am super cool and I dont care" ), 5 ) );
    }

    @Test
    public void testTokenSpecial() {

        Assert.assertEquals(
                "(See phillip@cool.com)",
                DocumentFragmentFormatter.format( makeEntry( 5, "(See phillip@cool.com)" ), 1 ) );
    }

    @Test
    @Ignore
    public void testMultiple() {
        Assert.assertEquals(
                "she is cool he is",
                DocumentFragmentFormatter.format( makeEntry( 7, "she is cool he is cool" ), 2 ) );

        Assert.assertEquals(
                "he is cool",
                DocumentFragmentFormatter.format( makeEntry( 18, "she is cool he is cool" ), 2 ) );

        Assert.assertEquals( "cool cool", DocumentFragmentFormatter.format( makeEntry( 0, "cool cool" ), 2 ) );

        Assert.assertEquals( "cool cool", DocumentFragmentFormatter.format( makeEntry( 5, "cool cool" ), 2 ) );

        Assert.assertEquals(
                "cool cool buzz cool",
                DocumentFragmentFormatter.format( makeEntry( 5, "cool cool buzz cool" ), 2 ) );

        Assert.assertEquals(
                "cool cool buzz",
                DocumentFragmentFormatter.format( makeEntry( 0, "cool cool buzz cool" ), 2 ) );

        Assert.assertEquals(
                "cool buzz cool",
                DocumentFragmentFormatter.format( makeEntry( 15, "cool cool buzz cool" ), 2 ) );

    }

    @Test
    public void testSymbols() {
        Assert.assertEquals(
                "a_cool_word",
                DocumentFragmentFormatter.format( makeEntry( 20, "this word is really a_cool_word" ), 0 ) );
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
