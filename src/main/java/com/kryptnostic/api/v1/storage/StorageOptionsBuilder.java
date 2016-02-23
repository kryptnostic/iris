package com.kryptnostic.api.v1.storage;

import java.util.UUID;

import javax.annotation.Nullable;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.storage.types.TypeUUIDs;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class StorageOptionsBuilder {
    private Optional<VersionedObjectKey> objectId;
    private Optional<VersionedObjectKey> parentObjectId;
    private boolean                      searchable;
    private boolean                      storeable;
    private boolean                      salted;
    private boolean                      inheritingOwnership;
    private boolean                      inheritingCryptoService;
    private Cypher                       cypher;
    private UUID                         type;

    public StorageOptionsBuilder() {
        objectId = Optional.absent();
        parentObjectId = Optional.absent();
        searchable = true;
        storeable = true;
        salted = false;
        cypher = Cypher.DEFAULT;
        inheritingCryptoService = false;
        inheritingOwnership = false;
        type = TypeUUIDs.DEFAULT_TYPE;
    }

    public StorageOptionsBuilder withId( @Nullable VersionedObjectKey objectKey ) {
        this.objectId = Optional.fromNullable( objectKey );
        return this;
    }

    public StorageOptionsBuilder withParentId( @Nullable VersionedObjectKey parentObjectKey ) {
        this.parentObjectId = Optional.fromNullable( parentObjectKey );
        return this;
    }

    public StorageOptionsBuilder withType( UUID type ) {
        this.type = type;
        return this;
    }

    public StorageOptionsBuilder searchable() {
        this.searchable = true;
        return this;
    }

    public StorageOptionsBuilder inheritOwner() {
        this.inheritingOwnership = true;
        return this;
    }

    public StorageOptionsBuilder inheritCryptoService() {
        this.inheritingCryptoService = true;
        return this;
    }

    public StorageOptionsBuilder storeable() {
        this.storeable = true;
        return this;
    }

    public StorageOptionsBuilder notSearchable() {
        this.searchable = false;
        return this;
    }

    public StorageOptionsBuilder notStoreable() {
        this.storeable = false;
        return this;
    }

    public StorageOptionsBuilder isSalted( boolean isSalted ) {
        this.salted = isSalted;
        return this;
    }

    public StorageOptionsBuilder cypherType( Cypher cypherType ) {
        this.cypher = cypherType;
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
                cypher,
                inheritingOwnership,
                inheritingCryptoService,
                type );
    }
}