package com.kryptnostic.api.v1.indexing;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.users.v1.UserKey;

public class BaseIndexingService implements IndexingService {
    private final Set<Analyzer> analyzers;
    private final UserKey user;
    public BaseIndexingService( UserKey user ) {
        analyzers = Sets.<Analyzer> newHashSet( new TokenizingWhitespaceAnalyzer() );
        this.user = user;
    }

    @Override
    public Set<Metadatum> index( String documentId, String document ) {
        Set<Metadatum> metadata = Sets.newHashSet();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<Integer>> invertedIndex = analyzer.analyze( document );
            for ( Entry<String, List<Integer>> entry : invertedIndex.entrySet() ) {
                String token = entry.getKey();
                List<Integer> locations = entry.getValue();
                metadata.add( new Metadatum( new DocumentId( documentId, user ), token, locations ) );
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
