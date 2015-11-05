package com.kryptnostic.v2.marshalling;

import java.io.IOException;

import com.kryptnostic.v2.types.TypedBytes;

public interface MarshallingService {
    TypedBytes toTypedBytes( Object object ) throws IOException;

    <T> T fromTypeBytes( TypedBytes object ) throws IOException;

    <T> T fromTypeBytes( TypedBytes object, Class<T> clazz ) throws IOException;
}
