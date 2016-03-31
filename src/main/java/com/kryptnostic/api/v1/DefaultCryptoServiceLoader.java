package com.kryptnostic.api.v1;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Map.Entry;
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
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

public class DefaultCryptoServiceLoader implements CryptoServiceLoader<UUID> {
    private static final Logger                       logger = LoggerFactory
                                                                     .getLogger( DefaultCryptoServiceLoader.class );

    private final LoadingCache<UUID, CryptoService> keyCache;
    final KeyStorageApi                             keyStorageApi;
    private final KryptnosticConnection               connection;
    private Cypher                                    cypher;

    public DefaultCryptoServiceLoader(
            final KryptnosticConnection connection,
            Cypher cypher ) {
        this.connection = connection;
        this.keyStorageApi = connection.getKeyStorageApi();
        this.cypher = cypher;
        keyCache = CacheBuilder.newBuilder().maximumSize( 1000 ).expireAfterWrite( 10, TimeUnit.MINUTES )
                .build( new CacheLoader<UUID, CryptoService>() {
                    @Override
                    public Map<UUID, CryptoService> loadAll( Iterable<? extends UUID> keys ) throws IOException,
                            SecurityConfigurationException {

                        Set<UUID> ids = ImmutableSet.copyOf( keys );

                        Map<VersionedObjectKey, BlockCiphertext> data = keyStorageApi
                                .getAesEncryptedCryptoServices( ids );
                        if ( data.size() != ids.size() ) {
                            throw new InvalidCacheLoadException( "Unable to retrieve all keys." );
                        }
                        Map<UUID, CryptoService> processedData = Maps.newHashMap();

                        for ( Entry<VersionedObjectKey, BlockCiphertext> entry : data.entrySet() ) {
                            BlockCiphertext crypto = entry.getValue();
                            if ( crypto != null ) {
                                CryptoService service = connection.newCryptoManager().getRsaCryptoService().decrypt(
                                        crypto.getContents(), // TODO: Is this correct???
                                        AesCryptoService.class );
                                processedData.put( entry.getKey().getObjectId(), service );
                            }
                        }
                        return processedData;
                    }

                    @Override
                    public CryptoService load( UUID key ) throws IOException, SecurityConfigurationException {
                        byte[] crypto = keyStorageApi.getObjectCryptoService( key );
                        if ( crypto == null ) {
                            try {
                                CryptoService cs = new AesCryptoService( DefaultCryptoServiceLoader.this.cypher );
                                put( key, cs );
                                return cs;
                            } catch (
                                    NoSuchAlgorithmException
                                    | InvalidAlgorithmParameterException
                                    | ExecutionException e ) {
                                logger.error( "Failed while trying to create new crypto service for object id: {} ",
                                        key );
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
    public Optional<CryptoService> get( UUID id ) throws ExecutionException {
        return Optional.fromNullable( keyCache.get( id ) );
    }

    @Override
    public void put( UUID id, CryptoService service ) throws ExecutionException {
        keyCache.put( id, service );
        try {
            byte[] cs = connection.newCryptoManager().getRsaCryptoService().encrypt( service );
            keyStorageApi.setObjectCryptoService( id, cs );
        } catch ( SecurityConfigurationException | IOException e ) {
            throw new ExecutionException( e );
        }
    }

    @Override
    public Map<UUID, CryptoService> getAll( Set<UUID> ids ) throws ExecutionException {
        return keyCache.getAllPresent( ids );
    }

    @Override
    public void clear() {
        keyCache.invalidateAll();
        keyCache.cleanUp();
    }
}