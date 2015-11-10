package com.kryptnostic.v2.types;

import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.collect.BiMap;
import com.google.common.collect.HashBiMap;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.storage.StorageClient;
import com.kryptnostic.api.v1.storage.StorageOptions;
import com.kryptnostic.api.v1.storage.StorageOptionsBuilder;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.storage.types.TypeUUIDs;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class KryptnosticTypeManager implements TypeManager {
    private static final Logger         logger = LoggerFactory
                                                       .getLogger( KryptnosticTypeManager.class );

    private final BiMap<UUID, Class<?>> registeredTypes;
    private final StorageClient         storageClient;

    public KryptnosticTypeManager(
            final StorageClient storageClient ) throws ClassNotFoundException, ResourceNotFoundException {
        this.storageClient = storageClient;

        // Initial type system

        Set<UUID> typeIds = storageClient.getObjectIdsByType( TypeUUIDs.TYPE );

        Map<UUID, String> typesMap = (Map<UUID, String>) storageClient.getStrings( typeIds );
        registeredTypes = HashBiMap.<UUID, Class<?>> create( typesMap.size() );
        for ( Entry<UUID, ?> entry : typesMap.entrySet() ) {
            String className = (String) entry.getValue();
            registeredTypes.put( entry.getKey(), Class.forName( className ) );
        }

    }

    @Override
    public Optional<Class<?>> get( UUID typeId ) {
        return Optional.<Class<?>> fromNullable( registeredTypes.get( typeId ) );
    }

    @Override
    public Map<UUID, Class<?>> getAll( Set<UUID> typeIds ) {
        Map<UUID, Class<?>> classMap = Maps.newHashMapWithExpectedSize( typeIds.size() );
        for ( UUID typeId : typeIds ) {
            classMap.put( typeId, registeredTypes.get( typeId ) );
        }
        return classMap;
    }

    @Override
    public Optional<UUID> getTypeId( Object object ) {
        return Optional.fromNullable( registeredTypes.inverse().get( object.getClass() ) );
    }

    @Override
    public VersionedObjectKey registerType( Class<?> clazz ) throws IrisException {
        String className = clazz.getCanonicalName();
        StorageOptions options = new StorageOptionsBuilder().withType( TypeUUIDs.TYPE ).build();
        VersionedObjectKey key;
        try {
            key = storageClient.storeObject( options, className );
        } catch (
                BadRequestException
                | SecurityConfigurationException
                | IrisException
                | ResourceLockedException
                | ResourceNotFoundException | IOException | ExecutionException e ) {
            logger.error( "Unable to register type for class {}.", clazz, e );
            throw new IrisException( e );
        }
        registeredTypes.put( key.getObjectId(), clazz );
        return key;
    }

    @Override
    public VersionedObjectKey registerTypeOfObject( Object object ) throws IrisException {
        return registerType( object.getClass() );
    }

    private  static final class ClassInformation {
        
    }
}
