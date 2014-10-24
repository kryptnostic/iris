package com.kryptnostic.api.v1.indexing;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.users.v1.UserKey;

public class SimpleIndexer implements Indexer {
    private final Set<Analyzer> analyzers;
    private final UserKey       user;

    public SimpleIndexer( UserKey user ) {
        analyzers = Sets.<Analyzer> newHashSet( new TokenizingWhitespaceAnalyzer() );
        this.user = user;
    }

    @Override
    public Set<Metadata> index( String documentId, String document ) {
        Set<Metadata> metadata = Sets.newHashSet();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<Integer>> invertedIndex = analyzer.analyze( document );
            for ( Entry<String, List<Integer>> entry : invertedIndex.entrySet() ) {
                String token = entry.getKey();
                List<Integer> locations = entry.getValue();
                metadata.add( new Metadata( new DocumentId( documentId, user ), token, locations ) );
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
