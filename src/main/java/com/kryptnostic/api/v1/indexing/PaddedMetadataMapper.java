package com.kryptnostic.api.v1.indexing;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.MappedMetadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;

public class PaddedMetadataMapper implements MetadataMapper {
    private static final Random      r           = new SecureRandom();
    private static final Logger      log         = LoggerFactory.getLogger( PaddedMetadataMapper.class );
    private final KryptnosticContext context;
    private static final int         BUCKET_SIZE = 100;

    public PaddedMetadataMapper( KryptnosticContext context ) {
        this.context = context;
    }

    @Override
    public MappedMetadata mapTokensToKeys(
            Set<Metadata> metadata,
            BitVector searchNonce,
            EncryptedSearchSharingKey sharingKey ) throws IrisException {

        /*
         * Let's balance the metadatum set and generate random nonces. Generally, the list of metadatum should be of
         * length one, but in rare cases collisions may occur. In the case of a collision we'll just store both at the
         * same location. In the future, we may want to have a specific number of retries before giving up and allowing
         * a collision. In theory this shouldn't be a security risk, because its hard for an attacker to force stuff
         * into the same bucket, unless they compromise the random number generator.
         */
        Map<BitVector, List<Metadata>> metadataMap = Maps.newHashMapWithExpectedSize( metadata.size() );

        log.info( "Generating metadatum." );
        for ( Metadata metadatum : metadata ) {
            String token = metadatum.getToken();
            List<Integer> locations = metadatum.getLocations();
            int fromIndex = 0, toIndex = Math.min( locations.size(), BUCKET_SIZE );
            do {

                BitVector indexForTerm;
                try {
                    indexForTerm = context.generateIndexForToken( token, searchNonce, sharingKey );
                } catch ( ResourceNotFoundException e ) {
                    throw new IrisException( e );
                }

                Metadata balancedMetadatum = new Metadata( metadatum.getDocumentId(), token, subListAndPad(
                        locations,
                        fromIndex,
                        toIndex ) );
                List<Metadata> metadatumList = metadataMap.get( indexForTerm );

                if ( metadatumList == null ) {
                    metadatumList = Lists.newArrayListWithExpectedSize( 1 );
                    metadataMap.put( indexForTerm, metadatumList );
                }
                metadatumList.add( balancedMetadatum );
                fromIndex += BUCKET_SIZE;
                toIndex += BUCKET_SIZE;
                if ( toIndex > locations.size() ) {
                    toIndex = locations.size();
                }
            } while ( fromIndex < toIndex );
        }
        return MappedMetadata.from( metadataMap );
    }

    private Iterable<Integer> subListAndPad( List<Integer> locations, int fromIndex, int toIndex ) {
        int paddingLength = BUCKET_SIZE - toIndex + fromIndex;
        List<Integer> padding = Lists.newArrayListWithCapacity( paddingLength );
        for ( int i = 0; i < paddingLength; ++i ) {
            int invalidLocation = r.nextInt();
            padding.add( invalidLocation < 0 ? invalidLocation : -invalidLocation );
        }

        return Iterables.concat( locations.subList( fromIndex, toIndex ), padding );
    }
}
