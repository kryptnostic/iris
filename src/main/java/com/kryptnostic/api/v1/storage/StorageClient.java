package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.storage.v2.models.ObjectMetadata;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public interface StorageClient {
    UUID storeObject( Object storeable );

    UUID storeObject( StorageOptions options, Object storeable ) throws BadRequestException,
            SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException;

    UUID registerType( Class<?> clazz );

    Object getObject( UUID id );

    <T> T getObject( UUID id, Class<T> clazz ) throws ResourceNotFoundException;

    <T> T getObject( UUID id, TypeReference<T> ref );

    Map<UUID, ?> getObjects( Set<UUID> ids ) throws ResourceNotFoundException;

    void uploadMetadata( List<MetadataRequest> metadata ) throws BadRequestException;

    void deleteMetadata( UUID id );

    void deleteObject( UUID id );

    Set<UUID> getObjectIds();

    Set<UUID> getObjectIds( int offset, int pageSize );

    Map<Integer, String> getObjectPreview( UUID objectId, List<Integer> locations, int wordRadius )
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException,
            ClassNotFoundException, IOException;

    Set<UUID> getObjectIdsByType( UUID type );

    Set<UUID> getObjectIdsByType( UUID type, int offset, int pageSize );

    ObjectMetadata getObjectMetadata( UUID id ) throws ResourceNotFoundException;
}
