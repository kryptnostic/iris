package com.kryptnostic.api.v1.indexing.analysis;

import java.util.List;
import java.util.Map;

import org.junit.Assert;
import org.junit.Test;

import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;

public class AnalyzerTests {
	private static final String doc = "This is a test document, with some fu(|<3d up $hit!";
	
	@Test
	public void testTokenizingWhitepsaceAnalyzer() {
		TokenizingWhitespaceAnalyzer analyzer = new TokenizingWhitespaceAnalyzer();
		
		Map<String,List<Integer>> invertedIndex = analyzer.analyze( doc );
		
		Assert.assertEquals(invertedIndex.keySet() , Sets.newHashSet( "This" , "is" , "a" , "test" , "document", "with", "some", "fu","3d", "hit", "up") );
	}
}
