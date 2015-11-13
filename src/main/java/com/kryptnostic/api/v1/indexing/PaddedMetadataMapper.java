package com.kryptnostic.api.v1.indexing;

import java.security.SecureRandom;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.indexing.v1.PaddedMetadata;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;

public class PaddedMetadataMapper implements MetadataMapper {
    private static final Random      r                    = new SecureRandom();
    private static final Base64      encoder              = new Base64();
    private static final Logger      log                  = LoggerFactory.getLogger( PaddedMetadataMapper.class );
    private final KryptnosticCryptoManager context;
    private static final int         MINIMUM_TOKEN_LENGTH = 1;

    public PaddedMetadataMapper( KryptnosticCryptoManager context ) {
        this.context = context;
    }

    @Override
    public Collection<PaddedMetadata> mapTokensToKeys(
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

        Map<String, PaddedMetadata> metadataMap = Maps.newHashMapWithExpectedSize( metadata.size() );

        int numAcceptedTokens = 0;

        log.info( "Generating metadatum." );
        for ( Metadata metadatum : metadata ) {
            String token = metadatum.getToken();
            if ( token.length() <= MINIMUM_TOKEN_LENGTH ) {
                continue;
            }
            numAcceptedTokens++;
            List<Integer> locations = metadatum.getLocations();

            byte[] indexForTerm = context.generateIndexForToken( token, objectIndexPair );

            String key = encoder.encodeAsString( indexForTerm );

            Metadata balancedMetadatum = new Metadata( metadatum.getObjectId(), token, subListAndPad(
                    locations,
                    bucketSize ) );

            PaddedMetadata pm = metadataMap.get( key );

            if ( pm == null ) {
                pm = new PaddedMetadata( indexForTerm, Lists.<Metadata> newArrayListWithExpectedSize( 1 ) );
                metadataMap.put( key, pm );
            }

            pm.getMetadata().add( balancedMetadatum );

        }
        log
                .trace(
                        "[PROFILE] MinLocations: {} MaxLocations: {} RawMetadataSize: {} ProcessedMetadataSize: {} AcceptedTokens: {}",
                        metadata.size(),
                        metadataMap.values().size(),
                        numAcceptedTokens );
        return metadataMap.values();
    }

    private List<Integer> subListAndPad( List<Integer> locations, int bucketSize ) {
        List<Integer> padding = Lists.newArrayListWithCapacity( bucketSize );
        padding.addAll( locations );
        for ( int i = locations.size(); i < bucketSize; ++i ) {
            int invalidLocation = r.nextInt();
            padding.add( invalidLocation < 0 ? invalidLocation : -invalidLocation );
        }

        return padding;
    }
}
