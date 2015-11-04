package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import javax.annotation.Nullable;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.kryptnostic.v2.storage.types.TypeUUIDs;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class StorageOptionBuilder {
    private Optional<UUID> objectId;
    private Optional<UUID> parentObjectId;
    private boolean        searchable;
    private boolean        storeable;
    private boolean        inheritingOwnership;
    private boolean        inheritingCryptoService;
    private UUID           type;

    public StorageOptionBuilder() {
        objectId = Optional.absent();
        parentObjectId = Optional.absent();
        searchable = true;
        storeable = true;
        inheritingCryptoService = false;
        inheritingOwnership = false;
        type = TypeUUIDs.DEFAULT_TYPE;
    }

    public StorageOptionBuilder withId( UUID objectId ) {
        this.objectId = Optional.fromNullable( objectId );
        return this;
    }

    public StorageOptionBuilder withParentId( @Nullable UUID parentObjectId ) {
        this.parentObjectId = Optional.fromNullable( parentObjectId );
        return this;
    }

    public StorageOptionBuilder withType( UUID type ) {
        this.type = type;
        return this;
    }

    public StorageOptionBuilder searchable() {
        this.searchable = true;
        return this;
    }

    public StorageOptionBuilder inheritOwner() {
        this.inheritingOwnership = true;
        return this;
    }

    public StorageOptionBuilder inheritCryptoService() {
        this.inheritingCryptoService = true;
        return this;
    }

    public StorageOptionBuilder storeable() {
        this.storeable = true;
        return this;
    }

    public StorageOptionBuilder notSearchable() {
        this.searchable = false;
        return this;
    }

    public StorageOptionBuilder notStoreable() {
        this.storeable = false;
        return this;
    }

    public StorageOptions build() {
        Preconditions.checkState( searchable || storeable, "Must storeable or searchable." );
        
        if ( inheritingCryptoService || inheritingOwnership ) {
            Preconditions.checkState( parentObjectId.isPresent(), "Parent object id required for inheritance." );
        }

        return new StorageOptions(
                objectId,
                parentObjectId,
                searchable,
                storeable,
                inheritingOwnership,
                inheritingCryptoService,
                type );
    }
}