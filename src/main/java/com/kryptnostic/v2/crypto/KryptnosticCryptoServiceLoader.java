package com.kryptnostic.v2.crypto;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.storage.models.VersionedObjectKeySet;

/**
 * Provider class for {@link CryptoService} objects used for encrypting and decrypting objects.
 *
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class KryptnosticCryptoServiceLoader implements CryptoServiceLoader {
    private static final Logger                                   logger = LoggerFactory
                                                                                 .getLogger( KryptnosticCryptoServiceLoader.class );

    private final LoadingCache<VersionedObjectKey, CryptoService> keyCache;
    private KeyStorageApi                                         keyStorageApi;
    private ObjectStorageApi                                      objectStorageApi;
    private KryptnosticConnection                                 connection;
    private Cypher                                                cypher;

    public KryptnosticCryptoServiceLoader(
            final KryptnosticConnection connection,
            final KeyStorageApi keyApi,
            ObjectStorageApi objectStorageApi,
            Cypher cypher ) {
        this.keyStorageApi = keyApi;
        this.objectStorageApi = objectStorageApi;
        this.connection = connection;
        this.cypher = cypher;
        keyCache = CacheBuilder.newBuilder().maximumSize( 1000 ).expireAfterWrite( 10, TimeUnit.MINUTES )
                // TODO: make this a separate class
                .build( new CacheLoader<VersionedObjectKey, CryptoService>() {
                    @Override
                    public Map<VersionedObjectKey, CryptoService> loadAll( Iterable<? extends VersionedObjectKey> keys )
                            throws IOException,
                            SecurityConfigurationException {
                        VersionedObjectKeySet ids = new VersionedObjectKeySet();

                        for ( VersionedObjectKey key : keys ) {
                            ids.add( key );
                        }

                        Map<VersionedObjectKey, byte[]> data = keyApi.getObjectCryptoServices( ids );
                        if ( data.size() != ids.size() ) {
                            throw new InvalidCacheLoadException( "Unable to retrieve all keys." );
                        }
                        Map<VersionedObjectKey, CryptoService> processedData = Maps.newHashMap();

                        for ( Map.Entry<VersionedObjectKey, byte[]> entry : data.entrySet() ) {
                            byte[] crypto = entry.getValue();
                            if ( crypto != null ) {
                                CryptoService service = connection.newCryptoManager().getRsaCryptoService().decrypt(
                                        crypto,
                                        AesCryptoService.class );
                                processedData.put( entry.getKey(), service );
                            }
                        }
                        return processedData;
                    }

                    @Override
                    public CryptoService load( VersionedObjectKey key ) throws IOException,
                            SecurityConfigurationException {
                        byte[] crypto = keyApi.getObjectCryptoService( key.getObjectId(), key.getVersion() );
                        if ( ( crypto == null ) ) {
                            try {
                                CryptoService cs = new AesCryptoService( KryptnosticCryptoServiceLoader.this.cypher );
                                put( key, cs );
                                return cs;
                            } catch (
                                    NoSuchAlgorithmException
                                    | InvalidAlgorithmParameterException
                                    | ExecutionException e ) {
                                logger.error( "Failed while trying to create new crypto service for object id: {} ",
                                        key, e );
                            }
                        }
                        return connection
                                .newCryptoManager()
                                .getRsaCryptoService()
                                .decrypt( crypto, AesCryptoService.class );
                    }
                } );
    }

    @Override
    public Optional<CryptoService> get( VersionedObjectKey id ) throws ExecutionException {
        return Optional.fromNullable( keyCache.get( id ) );
    }

    @Override
    public void put( VersionedObjectKey id, CryptoService service ) throws ExecutionException {
        keyCache.put( id, service );
        try {
            byte[] cs = connection.newCryptoManager().getRsaCryptoService().encrypt( service );
            keyStorageApi.setObjectCryptoService( id.getObjectId(), id.getVersion(), cs );
        } catch ( SecurityConfigurationException | IOException e ) {
            throw new ExecutionException( e );
        }
    }

    @Override
    public Map<VersionedObjectKey, CryptoService> getAll( Set<VersionedObjectKey> ids ) throws ExecutionException {
        return keyCache.getAllPresent( ids );
    }

    @Override
    public void clear() {
        keyCache.invalidateAll();
        keyCache.cleanUp();
    }

    @Override
    public Optional<CryptoService> getLatest( UUID id ) throws ExecutionException {
        return get( VersionedObjectKey.fromObjectMetadata( objectStorageApi.getObjectMetadata( id ) ) );
    }
}