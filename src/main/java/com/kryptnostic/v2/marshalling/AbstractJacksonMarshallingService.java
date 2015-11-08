package com.kryptnostic.v2.marshalling;

import java.io.IOException;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Charsets;
import com.kryptnostic.v2.storage.types.TypeUUIDs;
import com.kryptnostic.v2.types.TypeStorage;
import com.kryptnostic.v2.types.TypedBytes;

public abstract class AbstractJacksonMarshallingService implements MarshallingService {
    private final ObjectMapper mapper;
    private final TypeStorage resolver;
    
    protected AbstractJacksonMarshallingService( ObjectMapper mapper, TypeStorage resolver ) throws ClassNotFoundException {
        this.mapper = mapper;
        this.resolver = resolver;
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
