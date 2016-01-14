package com.kryptnostic.v2.indexing;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.analysis.TokenizingWhitespaceAnalyzer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.v2.indexing.metadata.BucketedMetadata;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class SimpleIndexer implements Indexer {
    private final Set<Analyzer> analyzers;

    public SimpleIndexer() {
        analyzers = Sets.<Analyzer> newHashSet( new TokenizingWhitespaceAnalyzer( DEFAULT_BUCKET_SIZE ) );
    }

    @Override
    public Set<BucketedMetadata> index( VersionedObjectKey objectId, String object ) {
        Set<BucketedMetadata> metadata = Sets.newHashSet();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<List<Integer>>> invertedIndex = analyzer.analyze( object );
            for ( Entry<String, List<List<Integer>>> entry : invertedIndex.entrySet() ) {
                String token = entry.getKey();
                List<List<Integer>> locations = entry.getValue();
                metadata.add( new BucketedMetadata( objectId, token, locations.size(), locations ) );
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
