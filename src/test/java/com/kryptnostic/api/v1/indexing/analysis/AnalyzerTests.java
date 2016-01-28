package com.kryptnostic.api.v1.indexing.analysis;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;

public class AnalyzerTests {

    private static final String DOC = "This is IS a test document, Is with some document fu(|<3d up $hit!";

    @Test
    public void testPatternMatchingAnalyzer() {
        PatternMatchingAnalyzer analyzer = new PatternMatchingAnalyzer();

        Set<String> expectedTokens =
                Sets.newHashSet( "this", "is", "test", "document", "with", "some", "fu", "3d", "hit", "up" );
        Assert.assertEquals(
                expectedTokens,
                analyzer.tokenize( DOC ) );

        Map<String, List<Integer>> expectedInvertedIndex = Maps.newHashMap();
        expectedInvertedIndex.put( "this", Lists.newArrayList( 0 ) );
        expectedInvertedIndex.put( "is", Lists.newArrayList( 5, 8, 28 ) );
        expectedInvertedIndex.put( "test", Lists.newArrayList( 13 ) );
        expectedInvertedIndex.put( "document", Lists.newArrayList( 18, 41 ) );
        expectedInvertedIndex.put( "with", Lists.newArrayList( 31 ) );
        expectedInvertedIndex.put( "some", Lists.newArrayList( 36 ) );
        expectedInvertedIndex.put( "fu", Lists.newArrayList( 50 ) );
        expectedInvertedIndex.put( "3d", Lists.newArrayList( 55 ) );
        expectedInvertedIndex.put( "hit", Lists.newArrayList( 62 ) );
        expectedInvertedIndex.put( "up", Lists.newArrayList( 58 ) );
        Assert.assertEquals(
                expectedInvertedIndex,
                analyzer.buildInvertedIndex( DOC ) );
    }
}
