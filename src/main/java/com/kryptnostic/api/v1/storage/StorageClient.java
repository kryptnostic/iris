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
import com.kryptnostic.v2.storage.models.LoadLevel;
import com.kryptnostic.v2.storage.models.ObjectMetadata;
import com.kryptnostic.v2.storage.models.ObjectMetadataNode;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public interface StorageClient {
    VersionedObjectKey registerType( Class<?> clazz ) throws IrisException;

    UUID storeObject( Object storeable );

    VersionedObjectKey storeObject( StorageOptions options, Object storeable ) throws BadRequestException,
            SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException, IOException, ExecutionException;

    VersionedObjectKey storeIndexedString( String s ) throws BadRequestException, SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException, IOException, ExecutionException;

    ObjectMetadata getObjectMetadata( UUID id ) throws ResourceNotFoundException;

    Object getObject( UUID id ) throws IOException, ExecutionException, SecurityConfigurationException;
    
    Object getObject( ObjectMetadata objectMetadata ) throws ResourceNotFoundException, ExecutionException,
            SecurityConfigurationException, IOException;

    <T> T getObject( UUID id, Class<T> clazz ) throws ResourceNotFoundException;

    <T> T getObject( UUID id, TypeReference<T> ref );

    ObjectMetadataNode getObjects( Set<UUID> objectIds, Map<UUID, LoadLevel> loadLevelsByTypeId )
            throws ResourceNotFoundException;

    Map<UUID, String> getStrings( Set<UUID> objectIds );

    void deleteMetadataForObjectId( UUID id );

    void deleteObject( UUID id );

    Set<UUID> getObjectIds();

    Set<UUID> getObjectIds( int offset, int pageSize );

    Map<Integer, String> getObjectPreview( UUID objectId, List<Integer> locations, int wordRadius )
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException,
            ClassNotFoundException, IOException;

    Set<UUID> getObjectIdsByType( UUID type );

    Set<UUID> getObjectIdsByType( UUID type, int offset, int pageSize );

}
