package com.kryptnostic.v2.marshalling;

import com.kryptnostic.api.v1.storage.StorageClient;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

public class SmileJacksonMarshallingService extends AbstractJacksonMarshallingService {

    public SmileJacksonMarshallingService( StorageClient storageClient ) throws ClassNotFoundException,
            ResourceNotFoundException {
        super( KodexObjectMapperFactory.getSmileMapper(), storageClient );
    }

}
