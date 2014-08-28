package com.kryptnostic.mock.services;

import java.util.Collection;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Preconditions;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.request.IndexableMetadata;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class MockKryptnosticMetadata implements MetadataApi {
    private final MockMetadataService metadataService = new MockMetadataService();
    private final Integer OK_STATUS = 200;

    @Override
    public BasicResponse<String> uploadMetadata(MetadataRequest metadata) throws BadRequestException {
        Preconditions.checkArgument(metadata != null, "metadata request cannot be null.");
        Collection<IndexableMetadata> metadataCollection = metadata.getMetadata();
        for (IndexableMetadata m : metadataCollection) {
            BitVector vector = m.getKey();
            Metadatum data = m.getData();
            metadataService.save(vector, data);
        }
        return new BasicResponse<String>("", OK_STATUS, true);
    }
}
