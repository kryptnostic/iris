package com.kryptnostic.api.v1.indexing;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.common.io.Resources;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;

public class IndexingTests {
    private static final Logger logger = LoggerFactory.getLogger( IndexingTests.class );

    private static Indexer      indexingService;

    @Test
    public void testIndexing() throws IOException {
        indexingService = new SimpleIndexer();

        String document = Resources.toString( Resources.getResource( "privacy.txt" ), Charsets.UTF_8 );
        logger.info( "Loaded privacy.txt" );
        long start = System.nanoTime();
        String documentId = Hashing.sha256().hashString( document, Charsets.UTF_8 ).toString();
        logger.info(
                "Hashed document of length {} in {} ms.",
                document.length(),
                TimeUnit.NANOSECONDS.toMillis( System.nanoTime() - start ) );

        start = System.nanoTime();
        Set<Metadata> metadata = indexingService.index( documentId, document );
        logger.info(
                "Indexed document of length {} in {} ms.",
                document.length(),
                TimeUnit.NANOSECONDS.toMillis( System.nanoTime() - start ) );
        Assert.assertNotNull( metadata );
        Assert.assertTrue( !metadata.isEmpty() );
    }

}
