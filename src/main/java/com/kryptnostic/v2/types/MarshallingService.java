package com.kryptnostic.v2.types;

import java.io.IOException;

public interface MarshallingService {
    TypedBytes toTypedBytes( Object object ) throws IOException;

    <T> T fromTypeBytes( TypedBytes object ) throws IOException;

    <T> T fromTypeBytes( TypedBytes object, Class<T> clazz ) throws IOException;
}
