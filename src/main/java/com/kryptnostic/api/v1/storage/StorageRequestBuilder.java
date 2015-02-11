package com.kryptnostic.api.v1.storage;

import com.kryptnostic.storage.v1.models.request.StorageRequest;

public class StorageRequestBuilder {
    private String  objectId;
    private String  objectBody;
    private boolean isSearchable;
    private boolean isStoreable;
    private String  type;

    public StorageRequestBuilder() {
        objectBody = null;
        objectId = null;
        isSearchable = true;
        isStoreable = true;
        type = null;
    }

    private StorageRequestBuilder clone( StorageRequestBuilder o ) {
        StorageRequestBuilder b = new StorageRequestBuilder();
        b.objectBody = o.objectBody;
        b.objectId = o.objectId;
        b.isSearchable = o.isSearchable;
        b.isStoreable = o.isStoreable;
        b.type = o.type;
        return b;
    }

    public StorageRequestBuilder withBody( String objectBody ) {
        StorageRequestBuilder b = clone( this );
        b.objectBody = objectBody;
        return b;
    }

    public StorageRequestBuilder withId( String objectId ) {
        StorageRequestBuilder b = clone( this );
        b.objectId = objectId;
        return b;
    }

    public StorageRequestBuilder withType( String type ) {
        StorageRequestBuilder b = clone( this );
        b.type = type;
        return b;
    }

    public StorageRequestBuilder searchable() {
        StorageRequestBuilder b = clone( this );
        b.isSearchable = true;
        return b;
    }

    public StorageRequestBuilder storeable() {
        StorageRequestBuilder b = clone( this );
        b.isStoreable = true;
        return b;
    }

    public StorageRequestBuilder notSearchable() {
        StorageRequestBuilder b = clone( this );
        b.isSearchable = false;
        return b;
    }

    public StorageRequestBuilder notStoreable() {
        StorageRequestBuilder b = clone( this );
        b.isStoreable = false;
        return b;
    }

    public StorageRequest build() {
        if ( objectBody == null ) {
            throw new IllegalStateException( "Object body must not be null" );
        }
        if ( !isSearchable && !isStoreable ) {
            throw new IllegalStateException( "Not searchable or storeable, so no-op" );
        }
        return new StorageRequest( objectId, objectBody, isSearchable, isStoreable, type );
    }
}