package com.kryptnostic.api.v1.indexing.metadata;

import java.util.List;
import java.util.Map;

import cern.colt.bitvector.BitVector;

import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;

public class BalancedMetadata implements Metadata {
    private final Map<BitVector, List<Metadatum>> metadataMap;
    private final List<BitVector> nonces;

    public BalancedMetadata(Map<BitVector, List<Metadatum>> metadataMap, List<BitVector> nonces) {
        this.metadataMap = metadataMap;
        this.nonces = nonces;
    }

    public Map<BitVector, List<Metadatum>> getMetadataMap() {
        return metadataMap;
    }

    public List<BitVector> getNonces() {
        return nonces;
    }

    public static Metadata from(Map<BitVector, List<Metadatum>> metadataMap, List<BitVector> nonces) {
        return new BalancedMetadata(metadataMap, nonces);
    }
}
