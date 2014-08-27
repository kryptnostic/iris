package com.kryptnostic.api.v1.indexing;

import java.security.SecureRandom;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.indexing.metadata.BalancedMetadata;
import com.kryptnostic.api.v1.indexing.metadata.BaseMetadatum;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;

public class BalancedMetadataKeyService implements MetadataKeyService {
    private static final Random r = new SecureRandom();
    private final KryptnosticContext context;
    private static final int BUCKET_SIZE = 100;

    public BalancedMetadataKeyService(KryptnosticContext context) {
        this.context = context;
    }

    public String getKey(String token, BitVector nonce) {
        BitVector tokenVector = Indexes.computeHashAndGetBits(token);

        return BitVectors.marshalBitvector(context.getSearchFunction().apply(tokenVector, nonce));
    }

    // TODO reuse nonces
    // TODO add nonces to context
    @Override
    public Metadata mapTokensToKeys(Set<Metadatum> metadata) {
        /*
         * Let's balance the metadatum set and generate random nonces. Generally, the list of metadatum should be of
         * length one, but in rare cases collisions may occur. In the case of a collision we'll just store both at the
         * same location. In the future, we may want to have a specific number of retries before giving up and allowing
         * a collision. In theory this shouldn't be a security risk, because its hard for an attacker to force stuff
         * into the same bucket, unless they compromise the random number generator.
         */
        Map<String, List<Metadatum>> metadataMap = Maps.newHashMapWithExpectedSize(metadata.size());
        List<BitVector> nonces = Lists.newArrayList();
        for (Metadatum metadatum : metadata) {
            String token = metadatum.getToken();
            List<Integer> locations = metadatum.getLocations();
            int fromIndex = 0, toIndex = Math.min(locations.size(), BUCKET_SIZE);
            do {
                Metadatum balancedMetadatum = new BaseMetadatum(metadatum.getDocumentId(), token, subListAndPad(
                        locations, fromIndex, toIndex));
                BitVector nonce = context.generateNonce();
                String key = getKey(token, nonce);
                nonces.add(nonce);
                List<Metadatum> metadatumList = metadataMap.get(key);
                // TODO: Retry a few times instead of just allowing collision.
                if (metadatumList == null) {
                    metadatumList = Lists.newArrayListWithExpectedSize(1);
                    metadataMap.put(key, metadatumList);
                }
                metadatumList.add(balancedMetadatum);
                fromIndex += BUCKET_SIZE;
                toIndex += BUCKET_SIZE;
                if (toIndex > locations.size()) {
                    toIndex = locations.size();
                }
            } while (fromIndex < toIndex);
        }
        return BalancedMetadata.from(metadataMap, nonces);
    }

    private Iterable<Integer> subListAndPad(List<Integer> locations, int fromIndex, int toIndex) {
        int paddingLength = BUCKET_SIZE - toIndex + fromIndex;
        List<Integer> padding = Lists.newArrayListWithCapacity(paddingLength);
        for (int i = 0; i < paddingLength; ++i) {
            int invalidLocation = r.nextInt();
            padding.add(invalidLocation < 0 ? invalidLocation : -invalidLocation);
        }

        return Iterables.concat(locations.subList(fromIndex, toIndex), padding);
    }
}
