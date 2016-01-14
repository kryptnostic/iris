package com.kryptnostic.api.v1.indexing.analysis;

import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.Sets;
import com.kryptnostic.v2.indexing.Indexer;

public class AnalyzerTests {
    private static final String doc = "This is a test document, with some fu(|<3d up $hit!";

    @Test
    public void testTokenizingWhitepsaceAnalyzer() {
        TokenizingWhitespaceAnalyzer analyzer = new TokenizingWhitespaceAnalyzer( Indexer.DEFAULT_BUCKET_SIZE );

        Map<String, List<List<Integer>>> invertedIndex = analyzer.analyze( doc );

        Assert.assertEquals(
                invertedIndex.keySet(),
                Sets.newHashSet( "this", "is", "a", "test", "document", "with", "some", "fu", "3d", "hit", "up" ) );
    }
}
