package com.kryptnostic.api.v1.indexing;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;

public class SimpleIndexer implements Indexer {
    private final Set<Analyzer> analyzers;

    public SimpleIndexer() {
        analyzers = Sets.<Analyzer> newHashSet( new TokenizingWhitespaceAnalyzer( 10 ) );
    }

    @Override
    public Set<Metadata> index( String objectId, String object ) {
        Set<Metadata> metadata = Sets.newHashSet();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<List<Integer>>> invertedIndex = analyzer.analyze( object );
            for ( Entry<String, List<List<Integer>>> entry : invertedIndex.entrySet() ) {
                String token = entry.getKey();
                List<Integer> locations = ImmutableList.copyOf( Iterables.concat( entry.getValue() ) );
                metadata.add( new Metadata( objectId, token, locations ) );
            }
        }
        return metadata;
    }

    @Override
    public boolean registerAnalyzer( Analyzer analyzer ) {
        return analyzers.add( analyzer );
    }

    @Override
    public Set<Analyzer> getAnalyzers() {
        return Collections.unmodifiableSet( analyzers );
    }

}
