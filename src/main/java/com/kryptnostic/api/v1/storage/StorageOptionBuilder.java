package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import javax.annotation.Nullable;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.storage.types.TypeUUIDs;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class StorageOptionBuilder {
    private Optional<VersionedObjectKey> objectId;
    private Optional<VersionedObjectKey> parentObjectId;
    private boolean                      searchable;
    private boolean                      storeable;
    private boolean                      inheritingOwnership;
    private boolean                      inheritingCryptoService;
    private UUID                         type;

    public StorageOptionBuilder() {
        objectId = Optional.absent();
        parentObjectId = Optional.absent();
        searchable = true;
        storeable = true;
        inheritingCryptoService = false;
        inheritingOwnership = false;
        type = TypeUUIDs.DEFAULT_TYPE;
    }

    public StorageOptionBuilder withId( @Nullable VersionedObjectKey objectKey ) {
        this.objectId = Optional.fromNullable( objectKey );
        return this;
    }

    public StorageOptionBuilder withParentId( @Nullable VersionedObjectKey parentObjectKey ) {
        this.parentObjectId = Optional.fromNullable( parentObjectKey );
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