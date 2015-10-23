package com.kryptnostic.v2.indexing;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;

import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.v2.indexing.metadata.Metadata;

public class SimpleIndexer implements Indexer {
    private final Set<Analyzer> analyzers;

    public SimpleIndexer() {
        analyzers = Sets.<Analyzer> newHashSet( new TokenizingWhitespaceAnalyzer() );
    }

    @Override
    public Set<Metadata> index( UUID objectId, String object ) {
        Set<Metadata> metadata = Sets.newHashSet();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<Integer>> invertedIndex = analyzer.analyze( object );
            for ( Entry<String, List<Integer>> entry : invertedIndex.entrySet() ) {
                String token = entry.getKey();
                List<Integer> locations = entry.getValue();
                metadata.add( new Metadata( objectId, token, locations.size(), locations ) );
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
