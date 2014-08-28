package com.kryptnostic.mock.services;

import java.util.Collection;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;

/**
 * In memory implementation of a metadata service for testing.
 * 
 * @author Nick Hewitt
 *
 */
public class MockMetadataService {
    private final Multimap<BitVector, Metadatum> indexMap = HashMultimap.create();
    
    public boolean save(BitVector key, Metadatum metadata) {
        indexMap.put(key, metadata);
        return true;
    }
    
    public Collection<Metadatum> get(BitVector key) {
        return indexMap.get(key);
    }
    
}
