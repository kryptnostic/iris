package com.kryptnostic.v2.marshalling;

import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.v2.types.TypeManager;

public class JsonJacksonMarshallingService extends AbstractJacksonMarshallingService {

    public JsonJacksonMarshallingService( TypeManager typeStorage ) throws ClassNotFoundException,
            ResourceNotFoundException {
        super( KodexObjectMapperFactory.getObjectMapper(), typeStorage );
    }

}
