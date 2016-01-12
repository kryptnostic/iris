package com.kryptnostic.v2.indexing;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.hash.Hashing;
import com.google.common.io.Resources;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.v2.indexing.metadata.BucketedMetadata;
import com.kryptnostic.v2.indexing.metadata.Metadata;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class IndexingTests {
    private static final Logger logger = LoggerFactory.getLogger( IndexingTests.class );

    private static Indexer      indexingService;

    @Test
    public void testIndexing() throws IOException {
        indexingService = new SimpleIndexer();

        String document = Resources.toString( Resources.getResource( "privacy.txt" ), Charsets.UTF_8 );
        logger.info( "Loaded privacy.txt" );
        long start = System.nanoTime();
        VersionedObjectKey documentId = new VersionedObjectKey(
                UUID.randomUUID(),
                RandomUtils.nextLong( 0, Long.MAX_VALUE ) );
        logger.info(
                "Hashed document of length {} in {} ms.",
                document.length(),
                TimeUnit.NANOSECONDS.toMillis( System.nanoTime() - start ) );

        start = System.nanoTime();
        Set<BucketedMetadata> metadata = indexingService.index( documentId, document );
        logger.info(
                "Indexed document of length {} in {} ms.",
                document.length(),
                TimeUnit.NANOSECONDS.toMillis( System.nanoTime() - start ) );
        Assert.assertNotNull( metadata );
        Assert.assertTrue( !metadata.isEmpty() );
    }

    @Test
    public void testMapping() throws IOException, IrisException {
        KryptnosticCryptoManager context = Mockito.mock( KryptnosticCryptoManager.class );
        Random r = new Random();

        byte[][] addresses = new byte[ 16 ][];
        String[] terms = new String[ 16 ];
        byte[] objectIndexPair = new byte[ 2064 ];

        r.nextBytes( objectIndexPair );
        for ( int i = 0; i < 16; ++i ) {
            terms[ i ] = RandomStringUtils.random( 10 );
            addresses[ i ] = new byte[ 16 ];
            r.nextBytes( addresses[ i ] );
            Mockito.when( context.generateIndexForToken( terms[ i ], objectIndexPair ) ).thenReturn( addresses[ i ] );
        }
        PaddedMetadataMapper mapper = new PaddedMetadataMapper( context );
        Assert.assertNotNull( context.generateIndexForToken( terms[ 0 ], objectIndexPair ) );
        Assert.assertArrayEquals( addresses[ 0 ], context.generateIndexForToken( terms[ 0 ], objectIndexPair ) );
        Set<BucketedMetadata> metadata = Sets.newHashSet();
        VersionedObjectKey id = new VersionedObjectKey( UUID.randomUUID(), RandomUtils.nextLong( 0, Long.MAX_VALUE ) );
        for ( int i = 0; i < 16; ++i ) {
            metadata.add(
                    new BucketedMetadata(
                            id,
                            terms[ i ],
                            1,
                            ImmutableList.<List<Integer>> of( Lists.newArrayList( 1, 2, 3, 4, 5, 6, 7, 8, 9, 0 ) ) ) );
        }

        Map<ByteBuffer, List<Metadata>> mappedMetadata = mapper.mapTokensToKeys( metadata, objectIndexPair );

        for ( int i = 0; i < 16; ++i ) {
            List<Metadata> metas = mappedMetadata.get( ByteBuffer
                    .wrap( Hashing.sha256().newHasher().putBytes( addresses[ i ] ).putInt( 0 ).hash().asBytes() ) );
            Assert.assertNotNull( metas );
//            Assert.assertTrue( "All metadatas must be present", metadata.containsAll( metas ) );
//            metadata.removeAll( metas );
        }

//        Assert.assertTrue( "All metas should have been removed", metadata.isEmpty() );
        logger.info( "Data: {}", mappedMetadata.values() );
    }
}
