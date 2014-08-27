package com.kryptnostic.mock.services;

import java.util.Collection;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Preconditions;
import com.kryptnostic.api.v1.client.web.MetadataApi;
import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.models.IndexableMetadata;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.BasicResponse;
import com.kryptnostic.bitwise.BitVectors;

public class MockKryptnosticMetadata implements MetadataApi {
    private final MockMetadataService metadataService = new MockMetadataService();
    private final Integer OK_STATUS = 200;
    
    @Override
    public BasicResponse<String> uploadMetadata(MetadataRequest metadata) throws BadRequestException {
        Preconditions.checkArgument(metadata != null, "metadata request cannot be null.");
        Collection<IndexableMetadata> metadataCollection = metadata.getMetadata();
        for (IndexableMetadata m : metadataCollection) {
            String key = m.getKey();
            BitVector vector = BitVectors.unmarshalBitvector(key);
            String data = m.getData();
            metadataService.save(vector, data);
        }
        return new BasicResponse<String>("", OK_STATUS, true);
    }
}
