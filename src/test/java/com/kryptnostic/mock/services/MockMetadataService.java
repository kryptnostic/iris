package com.kryptnostic.mock.services;

import java.util.Collection;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;

/**
 * In memory implementation of a metadata service for testing.
 * 
 * @author Nick Hewitt
 *
 */
public class MockMetadataService {
    private final Multimap<BitVector, String> indexMap = HashMultimap.create();
    
    public boolean save(BitVector key, String metadata) {
        indexMap.put(key, metadata);
        return true;
    }
    
    public Collection<String> get(BitVector key) {
        return indexMap.get(key);
    }
    
}
