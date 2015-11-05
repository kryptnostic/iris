package com.kryptnostic.v2.marshalling;

import com.kryptnostic.api.v1.storage.StorageClient;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

public class JsonJacksonMarshallingService extends AbstractJacksonMarshallingService {

    public JsonJacksonMarshallingService( StorageClient storageClient ) throws ClassNotFoundException,
            ResourceNotFoundException {
        super( KodexObjectMapperFactory.getObjectMapper(), storageClient );
    }

}
