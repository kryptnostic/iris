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
    private boolean        isSearchable;
    private boolean        isStoreable;
    private boolean        inheritingOwnership;
    private boolean        inheritingCryptoService;
    private UUID           type;

    public StorageOptionBuilder() {
        objectId = Optional.absent();
        parentObjectId = Optional.absent();
        isSearchable = true;
        isStoreable = true;
        inheritingCryptoService = false;
        inheritingOwnership = false;
        type = TypeUUIDs.UTF8_STRING;
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
        this.isSearchable = true;
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
        this.isStoreable = true;
        return this;
    }

    public StorageOptionBuilder notSearchable() {
        this.isSearchable = false;
        return this;
    }

    public StorageOptionBuilder notStoreable() {
        this.isStoreable = false;
        return this;
    }

    public StorageOptions build() {
        Preconditions.checkState( isSearchable || isStoreable, "Must storeable or searchable." );
        
        if ( inheritingCryptoService || inheritingOwnership ) {
            Preconditions.checkState( parentObjectId.isPresent(), "Parent object id required for inheritance." );
        }

        return new StorageOptions(
                objectId,
                parentObjectId,
                isSearchable,
                isStoreable,
                inheritingOwnership,
                inheritingCryptoService,
                type );
    }
}