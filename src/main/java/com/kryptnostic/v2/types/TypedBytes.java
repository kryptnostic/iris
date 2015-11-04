package com.kryptnostic.v2.types;

import java.util.UUID;

public class TypedBytes {
    private final byte[] bytes;
    private final UUID   type;

    public TypedBytes( byte[] bytes, UUID type ) {
        this.bytes = bytes;
        this.type = type;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public UUID getType() {
        return type;
    }
}
