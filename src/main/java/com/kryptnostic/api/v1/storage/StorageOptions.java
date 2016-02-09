package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import com.google.common.base.Optional;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.v2.storage.models.CreateObjectRequest;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class StorageOptions {
    public static final boolean                LOCK_DEFAULT                   = true;
    public static final boolean                INHERIT_OWNERSHIP_DEFAULT      = true;
    public static final boolean                INHERIT_CRYPTO_SERVICE_DEFAULT = true;
    private final Optional<VersionedObjectKey> objectId;
    private final Optional<VersionedObjectKey> parentObjectId;
    private final boolean                      isSearchable;
    private final boolean                      isStoreable;
    private final boolean                      inheritOwnership;
    private final boolean                      inheritCryptoService;
    private final Cypher                       cypherType;
    private final UUID                         type;

    public StorageOptions(
            Optional<VersionedObjectKey> objectId,
            Optional<VersionedObjectKey> parentObjectId,
            boolean isSearchable,
            boolean isStoreable,
            boolean isSalted,
            Cypher cypherType,
            boolean inheritOwnership,
            boolean inheritCryptoService,
            UUID type ) {
        super();
        this.objectId = objectId;
        this.parentObjectId = parentObjectId;
        this.isSearchable = isSearchable;
        this.isStoreable = isStoreable;
        this.inheritOwnership = inheritOwnership;
        this.inheritCryptoService = inheritCryptoService;
        this.cypherType = cypherType;
        this.type = type;
    }

    public static StorageOptionsBuilder builder() {
        return new StorageOptionsBuilder();
    }

    public UUID getType() {
        return type;
    }

    public Optional<VersionedObjectKey> getParentObjectId() {
        return parentObjectId;
    }

    public Optional<VersionedObjectKey> getObjectId() {
        return objectId;
    }

    public boolean isSearchable() {
        return isSearchable;
    }

    public boolean isStoreable() {
        return isStoreable;
    }

    public Cypher getCypherType() {
        return cypherType;
    }

    public CreateObjectRequest toCreateObjectRequest() {
        return toCreateObjectRequest( LOCK_DEFAULT );
    }

    public CreateObjectRequest toCreateObjectRequest( boolean locked ) {
        return new CreateObjectRequest(
                type,
                parentObjectId,
                objectId,
                cypherType,
                Optional.<Boolean> of( inheritOwnership ),
                Optional.<Boolean> of( inheritCryptoService ),
                Optional.<Boolean> of( locked ) );
    }
}
