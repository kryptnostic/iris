package com.kryptnostic.v2.indexing;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Random;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.indexing.analysis.PatternMatchingAnalyzer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class BucketingAndPaddingIndexer implements Indexer {

    private static final int DEFAULT_BUCKET_SIZE = 10;
    private static final Analyzer DEFAULT_ANALYZER = new PatternMatchingAnalyzer();
    private static final Random RANDOM = new SecureRandom();

    private final Analyzer analyzer;
    private final int bucketSize;

    public BucketingAndPaddingIndexer( Analyzer analyzer, int bucketSize ) {
        this.analyzer = analyzer;
        this.bucketSize = bucketSize;
    }

    public BucketingAndPaddingIndexer() {
        this( DEFAULT_ANALYZER, DEFAULT_BUCKET_SIZE );
    }

    @Override
    public List<InvertedIndexSegment> index( VersionedObjectKey objectKey, String contents ) {
        List<InvertedIndexSegment> result = Lists.newArrayList();
        Map<String, List<Integer>> invertedIndex = analyzer.buildInvertedIndex( contents );
        for (Map.Entry<String, List<Integer>> e : invertedIndex.entrySet()) {
            String token = e.getKey();
            List<Integer> allLocations = e.getValue();
            for (List<Integer> bucket : Iterables.partition( allLocations, bucketSize )) {
                List<Integer> paddedBucket = Lists.newArrayList(bucket);
                while (paddedBucket.size() < bucketSize) {
                    paddedBucket.add( RANDOM.nextInt() );
                }
                result.add( new InvertedIndexSegment( objectKey, token, paddedBucket ) );
            }
        }
        return result;
    }

}
