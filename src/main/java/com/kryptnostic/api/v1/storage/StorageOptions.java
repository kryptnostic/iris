package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import com.google.common.base.Optional;

public class StorageOptions {
    private final Optional<UUID> objectId;
    private final Optional<UUID> parentObjectId;
    private final boolean        isSearchable;
    private final boolean        isStoreable;
    private final UUID         type;

    public StorageOptions(
            Optional<UUID> objectId,
            Optional<UUID> parentObjectId,
            boolean isSearchable,
            boolean isStoreable,
            boolean inheritOwner,
            boolean inheritCryptoService,
            UUID type ) {
        super();
        this.objectId = objectId;
        this.parentObjectId = parentObjectId;
        this.isSearchable = isSearchable;
        this.isStoreable = isStoreable;
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

}
