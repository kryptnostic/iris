package com.kryptnostic.v2.marshalling;

import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.v2.types.TypeStorage;

public class JsonJacksonMarshallingService extends AbstractJacksonMarshallingService {

    public JsonJacksonMarshallingService( TypeStorage typeStorage ) throws ClassNotFoundException,
            ResourceNotFoundException {
        super( KodexObjectMapperFactory.getObjectMapper(), typeStorage );
    }

}
