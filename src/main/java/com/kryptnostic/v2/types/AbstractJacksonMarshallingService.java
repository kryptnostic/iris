package com.kryptnostic.v2.types;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.kryptnostic.api.v1.storage.StorageClient;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.v2.storage.types.TypeUUIDs;

public abstract class AbstractJacksonMarshallingService implements MarshallingService {
    private final ObjectMapper mapper;
    private final TypeResolver resolver;

    protected AbstractJacksonMarshallingService( ObjectMapper mapper, StorageClient storageClient ) throws ClassNotFoundException,
            ResourceNotFoundException {
        this.mapper = mapper;
        this.resolver = new KryptnosticTypesLoader( storageClient );
    }

    @Override
    public TypedBytes toTypedBytes( Object object ) throws IOException {
        byte[] bytes;
        UUID typeId;

        if ( object instanceof String ) {
            bytes = ( (String) object ).getBytes( Charsets.UTF_8 );
            typeId = TypeUUIDs.UTF8_STRING;
        } else {
            bytes = mapper.writeValueAsBytes( object );
            typeId = resolver.getTypeId( object ).get();
        }

        return new TypedBytes( bytes, typeId );
    }

    @SuppressWarnings( "unchecked" )
    @Override
    public <T> T fromTypeBytes( TypedBytes object ) throws IOException {
        return (T) fromTypeBytes( object, resolver.get( object.getType() ).get() );
    }

    @Override
    public <T> T fromTypeBytes( TypedBytes object, Class<T> clazz ) throws IOException {
        return mapper.readValue( object.getBytes(), clazz );
    }

}
