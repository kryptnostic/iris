package com.kryptnostic.api.v1;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RetrofitError;

import com.google.common.base.Optional;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.model.ByteArrayEnvelope;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;

public class DefaultCryptoServiceLoader implements CryptoServiceLoader {
    private static final Logger                       logger = LoggerFactory
                                                                     .getLogger( DefaultCryptoServiceLoader.class );

    private final LoadingCache<String, CryptoService> keyCache;
    private final DirectoryApi                        directoryApi;
    private final KryptnosticConnection               connection;
    private Cypher                                    cypher;

    public DefaultCryptoServiceLoader(
            final KryptnosticConnection connection,
            Cypher cypher ) {
        this.connection = connection;
        this.directoryApi = connection.getDirectoryApi();
        this.cypher = cypher;
        keyCache = CacheBuilder.newBuilder().maximumSize( 1000 ).expireAfterWrite( 10, TimeUnit.MINUTES )
                .build( new CacheLoader<String, CryptoService>() {
                    @Override
                    public Map<String, CryptoService> loadAll( Iterable<? extends String> keys ) throws IOException,
                            SecurityConfigurationException {

                        Set<String> ids = ImmutableSet.copyOf( keys );

                        Map<String, byte[]> data = directoryApi.getObjectCryptoServices( ids );
                        if ( data.size() != ids.size() ) {
                            throw new InvalidCacheLoadException( "Unable to retrieve all keys." );
                        }
                        Map<String, CryptoService> processedData = Maps.newHashMap();

                        for ( Map.Entry<String, byte[]> entry : data.entrySet() ) {
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
                    public CryptoService load( String key ) throws IOException, SecurityConfigurationException {
                        byte[] crypto = null;
                        try {
                            crypto = directoryApi.getObjectCryptoService( key ).getData();
                        } catch ( RetrofitError e ) {
                            logger.error( "Failed to load crypto service from backend for id {} ", key, e );
                            throw new IOException( e );
                        }
                        if ( ( crypto == null ) ) {
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
    public Optional<CryptoService> get( String id ) throws ExecutionException {
        return Optional.fromNullable( keyCache.get( id ) );
    }

    @Override
    public void put( String id, CryptoService service ) throws ExecutionException {
        keyCache.put( id, service );
        try {
            byte[] cs = connection.newCryptoManager().getRsaCryptoService().encrypt( service );
            directoryApi.setObjectCryptoService( id, new ByteArrayEnvelope( cs ) );
        } catch ( SecurityConfigurationException | IOException e ) {
            throw new ExecutionException( e );
        }
    }

    @Override
    public Map<String, CryptoService> getAll( Set<String> ids ) throws ExecutionException {
        return keyCache.getAllPresent( ids );
    }

    @Override
    public void clear() {
        keyCache.invalidateAll();
        keyCache.cleanUp();
    }
}