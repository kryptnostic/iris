package com.kryptnostic.v2.types;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.google.common.base.Optional;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

/**
 * This class is the interface for registering simple types. For the moment we do not provide direct support for
 * container types. Container types should have type information capture by either creating an explicit child child
 * type.
 * 
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public interface TypeManager {
    Optional<Class<?>> get( UUID typeId );

    Optional<UUID> getTypeId( Object object );

    VersionedObjectKey registerType( Class<?> clazz ) throws IrisException;

    VersionedObjectKey registerTypeOfObject( Object object ) throws IrisException;

    Map<UUID, Class<?>> getAll( Set<UUID> typeIds );
}
