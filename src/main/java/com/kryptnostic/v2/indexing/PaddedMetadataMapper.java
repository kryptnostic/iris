package com.kryptnostic.v2.indexing;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.v2.indexing.metadata.Metadata;
import com.kryptnostic.v2.indexing.metadata.MetadataMapper;

public class PaddedMetadataMapper implements MetadataMapper {
    private static final Random            r                    = new SecureRandom();
    private static final Logger            loggger              = LoggerFactory.getLogger( PaddedMetadataMapper.class );
    private static final int               MINIMUM_TOKEN_LENGTH = 1;

    private final KryptnosticCryptoManager cryptoManager;

    public PaddedMetadataMapper( KryptnosticCryptoManager cryptoManager ) {
        this.cryptoManager = cryptoManager;
    }

    @Override
    public Map<ByteBuffer, List<Metadata>> mapTokensToKeys(
            Set<Metadata> metadata,
            byte[] objectIndexPair )
            throws IrisException {

        /*
         * Let's balance the metadatum set and generate random nonces. Generally, the list of metadatum should be of
         * length one, but in rare cases collisions may occur. In the case of a collision we'll just store both at the
         * same location. In the future, we may want to have a specific number of retries before giving up and allowing
         * a collision. In theory this shouldn't be a security risk, because its hard for an attacker to force stuff
         * into the same bucket, unless they compromise the random number generator.
         */

        int bucketSize = 0;
        for ( Metadata m : metadata ) {
            bucketSize = Math.max( bucketSize, m.getLocations().size() );
        }

        Map<ByteBuffer, List<Metadata>> metadataMap = Maps.newHashMapWithExpectedSize( metadata.size() );

        int numAcceptedTokens = 0;

        loggger.info( "Generating metadatum." );
        for ( Metadata metadatum : metadata ) {
            String term = metadatum.getTerm();
            if ( term.length() <= MINIMUM_TOKEN_LENGTH ) {
                continue;
            }
            numAcceptedTokens++;
            List<Integer> locations = metadatum.getLocations();

            byte[] indexForTerm = cryptoManager.generateIndexForToken( term, objectIndexPair );

            ByteBuffer key = ByteBuffer.wrap( indexForTerm );

            Metadata balancedMetadatum = new Metadata(
                    metadatum.getObjectKey(),
                    term,
                    metadatum.getLength(),
                    subListAndPad(
                            locations,
                            bucketSize ) );

            List<Metadata> pm = metadataMap.get( key );

            if ( pm == null ) {
                pm = Lists.newArrayList();
                metadataMap.put( key, pm );
            }

            pm.add( balancedMetadatum );

        }
        loggger
                .info(
                        "[PROFILE] MinLocations: {} MaxLocations: {} RawMetadataSize: {} ProcessedMetadataSize: {} AcceptedTokens: {}",
                        metadata.size(),
                        metadataMap.values().size(),
                        numAcceptedTokens );
        return metadataMap;
    }

    private List<Integer> subListAndPad( List<Integer> locations, int bucketSize ) {
        List<Integer> padding = Lists.newArrayListWithCapacity( bucketSize );
        padding.addAll( locations );
        for ( int i = locations.size(); i < bucketSize; ++i ) {
            padding.add( r.nextInt() );
        }

        return padding;
    }

}
