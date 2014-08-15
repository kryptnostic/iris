package com.kryptnostic.client.tests;

import org.junit.Test;

import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.linear.BitUtils;

public class ClientTests {
    
    private static final int LENGTH = 512;

    @Test
    public void initializeTest() {
        
        
    }

    @Test
    public void uploadMetadataTest() {

        // store some metadata
        String key = BitVectors.marshalBitvector(BitUtils.randomVector(LENGTH));
        

    }

}
