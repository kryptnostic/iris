package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import com.google.common.base.Optional;
import com.kryptnostic.storage.v2.models.CreateObjectRequest;

public class StorageOptions {
    private static final boolean    LOCK_DEFAULT = true;
    private final Optional<UUID>    objectId;
    private final Optional<UUID>    parentObjectId;
    private final boolean           isSearchable;
    private final boolean           isStoreable;
    private final Optional<Boolean> inheritOwnership;
    private final Optional<Boolean> inheritCryptoService;
    private final UUID              type;

    public StorageOptions(
            Optional<UUID> objectId,
            Optional<UUID> parentObjectId,
            boolean isSearchable,
            boolean isStoreable,
            Optional<Boolean> inheritOwnership,
            Optional<Boolean> inheritCryptoService,
            UUID type ) {
        super();
        this.objectId = objectId;
        this.parentObjectId = parentObjectId;
        this.isSearchable = isSearchable;
        this.isStoreable = isStoreable;
        this.inheritOwnership = inheritOwnership;
        this.inheritCryptoService = inheritCryptoService;
        this.type = type;
    }

    public static StorageOptionBuilder builder() {
        return new StorageOptionBuilder();
    }

    public UUID getType() {
        return type;
    }

    public Optional<UUID> getParentObjectId() {
        return parentObjectId;
    }

    public Optional<UUID> getObjectId() {
        return objectId;
    }

    public boolean isSearchable() {
        return isSearchable;
    }

    public boolean isStoreable() {
        return isStoreable;
    }

    public CreateObjectRequest toCreateObjectRequest() {
        return toCreateObjectRequest( LOCK_DEFAULT );
    }

    public CreateObjectRequest toCreateObjectRequest( boolean locked ) {
        return new CreateObjectRequest(
                type,
                parentObjectId,
                objectId,
                inheritOwnership,
                inheritCryptoService,
                Optional.<Boolean> of( locked ) );
    }
}
