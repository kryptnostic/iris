package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.indexing.BucketingAndPaddingIndexer;
import com.kryptnostic.v2.indexing.Indexer;
import com.kryptnostic.v2.indexing.InvertedIndexSegment;
import com.kryptnostic.v2.marshalling.JsonJacksonMarshallingService;
import com.kryptnostic.v2.marshalling.MarshallingService;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.storage.api.ObjectListingApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;
import com.kryptnostic.v2.storage.models.CreateIndexSegmentRequest;
import com.kryptnostic.v2.storage.models.CreateObjectRequest;
import com.kryptnostic.v2.storage.models.LoadLevel;
import com.kryptnostic.v2.storage.models.ObjectMetadata;
import com.kryptnostic.v2.storage.models.ObjectMetadata.CryptoMaterial;
import com.kryptnostic.v2.storage.models.ObjectMetadataEncryptedNode;
import com.kryptnostic.v2.storage.models.ObjectMetadataNode;
import com.kryptnostic.v2.storage.models.ObjectTreeLoadRequest;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.storage.types.TypeUUIDs;
import com.kryptnostic.v2.types.KryptnosticTypeManager;
import com.kryptnostic.v2.types.TypeManager;
import com.kryptnostic.v2.types.TypedBytes;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultStorageClient implements StorageClient {
    public static final byte[]          ZERO_LENGTH_BYTE_ARRAY = new byte[ 0 ];
    private static final Logger         logger                 = LoggerFactory.getLogger( StorageClient.class );
    private static final Random         SECURE_RANDOM          = new SecureRandom();

    /**
     * Server-side
     */
    private final KryptnosticConnection connection;
    private final ObjectStorageApi      objectApi;
    private final ObjectListingApi      listingApi;
    private final SearchApi             searchApi;

    /**
     * Client-side
     */
    private final Indexer               indexer;
    private final CryptoServiceLoader   loader;
    private final MarshallingService    marshaller;
    private final TypeManager           typeManager;
    private final KryptnosticCryptoManager cryptoManager;

    public DefaultStorageClient(
            KryptnosticConnection connection ) throws ClassNotFoundException,
                    ResourceNotFoundException,
                    IOException,
                    ExecutionException,
                    SecurityConfigurationException {
        this.connection = connection;
        this.objectApi = connection.getObjectStorageApi();
        this.listingApi = connection.getObjectListingApi();
        this.searchApi = connection.getSearchApi();
        this.indexer = new BucketingAndPaddingIndexer();
        this.typeManager = new KryptnosticTypeManager( this );
        this.marshaller = new JsonJacksonMarshallingService( this.typeManager );
        this.loader = Preconditions.checkNotNull(
                connection.getCryptoServiceLoader(),
                "CryptoServiceLoader from KryptnosticConnection cannot be null." );
        this.cryptoManager = connection.newCryptoManager();
    }

    private CryptoService getOrCreateObjectCryptoService( VersionedObjectKey objectKey )
            throws ExecutionException, ResourceNotFoundException {
        Optional<CryptoService> maybeObjectCryptoService = loader.get( objectKey );
        if ( !maybeObjectCryptoService.isPresent() ) {
            // TODO: Centralize error messages somewhere so that we can manage error messages and resources.
            logger.error( "Unable to get or create an object crypto service for object: {} ", objectKey );
            throw new ResourceNotFoundException( "Unable to get or create an object crypto service for object "
                    + objectKey.toString() );
        }
        CryptoService objectCryptoService = maybeObjectCryptoService.get();
        return objectCryptoService;
    }

    @Override
    public VersionedObjectKey storeObject( StorageOptions req, Object storeable )
            throws IOException, ExecutionException, ResourceNotFoundException, SecurityConfigurationException,
            IrisException {

        CreateObjectRequest createObjectRequest = req.toCreateObjectRequest();
        VersionedObjectKey objectKey = objectApi.createObject( createObjectRequest );

        CryptoService objectCryptoService = getOrCreateObjectCryptoService( objectKey );

        byte[] actualBytes = null;
        if ( storeable instanceof byte[] ) {
            actualBytes = (byte[]) storeable;
        } else if ( storeable instanceof String ) {
            actualBytes = ( (String) storeable ).getBytes();
        } else {
            actualBytes = marshaller.toTypedBytes( storeable ).getBytes();
        }

        if ( req.isStoreable() ) {
            // TODO: Add BLOCK chunking
            BlockCiphertext ciphertext = objectCryptoService.encrypt( actualBytes );

            storeObject( objectKey, ciphertext, createObjectRequest.getRequiredCryptoMaterials() );
        }

        if ( req.isSearchable() && ( storeable instanceof String ) ) {
            // Setting up sharing is only required if object is searchable.
            byte[] objectIndexPair = provisionSearchPairAndReturnCorrespondingIndexPair( objectKey );
            makeObjectSearchable( objectKey, (String) storeable, objectIndexPair );
        }

        return objectKey;
    }

    // See http://wiki.krypt.int/pages/viewpage.action?pageId=13140089
    private void makeObjectSearchable( VersionedObjectKey objectKey, String contents, byte[] objectIndexPair )
            throws IOException, ExecutionException, ResourceNotFoundException, SecurityConfigurationException,
            IrisException {

        Stopwatch watch = Stopwatch.createStarted();
        List<InvertedIndexSegment> indexSegments = indexer.index( objectKey, contents );
        logger.trace( "[PROFILE] indexer took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        logger.trace( "[PROFILE] {} inverted index segments generated", indexSegments.size() );

        Collections.shuffle( indexSegments, SECURE_RANDOM );

        watch.reset().start();

        int N = indexSegments.size();
        int rangeStart = searchApi.getAndAddSegmentCount( objectKey.getObjectId(), N);
        for (int j = 0; j < N; j++) {
            InvertedIndexSegment indexSegment = indexSegments.get( j );
            byte[] baseAddress = cryptoManager.generateIndexForToken(
                    indexSegment.getToken(),
                    objectIndexPair );
            byte[] address = Hashing
                    .sha256()
                    .newHasher()
                    .putBytes( baseAddress )
                    .putInt( rangeStart + j )
                    .hash()
                    .asBytes();
            VersionedObjectKey indexSegmentKey =
                    objectApi.createIndexSegment( new CreateIndexSegmentRequest( address ) );

            CryptoService objectCryptoService = getOrCreateObjectCryptoService( objectKey );
            BlockCiphertext encryptedIndexSegment = objectCryptoService.encrypt(
                    marshaller.toTypedBytes( indexSegment ).getBytes() );

            objectApi.setObjectFromBlockCiphertext(
                    indexSegmentKey.getObjectId(),
                    indexSegmentKey.getVersion(),
                    encryptedIndexSegment );
        }

        logger.trace(
                "[PROFILE] computing addresses, encrypting index segments, and uploading took {} ms",
                watch.elapsed( TimeUnit.MILLISECONDS ) );
    }

    private byte[] provisionSearchPairAndReturnCorrespondingIndexPair( VersionedObjectKey key ) {
        KryptnosticEngine engine = connection.getKryptnosticEngine();

        Stopwatch watch = Stopwatch.createStarted();
        byte[] objectIndexPair = engine.getObjectIndexPair();
        byte[] objectSearchPair = engine.getObjectSearchPairFromObjectIndexPair( objectIndexPair );
        logger.trace( "[PROFILE] generating sharing key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        // TODO: Centralize these lengths in KryptnosticEngine
        Preconditions.checkState( objectSearchPair.length == KryptnosticEngine.SEARCH_PAIR_LENGTH,
                "Search pair must be 2080 bytes." );
        Preconditions.checkState( objectIndexPair.length == KryptnosticEngine.INDEX_PAIR_LENGTH,
                "Index pair must be 2064 bytes." );

        watch.reset().start();
        connection.newCryptoManager().registerObjectSearchPair( key, new ObjectSearchPair( objectSearchPair ) );
        logger.trace( "[PROFILE] submitting bridge key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        return objectIndexPair;
    }

    private void storeObject(
            VersionedObjectKey objectKey,
            BlockCiphertext ciphertext,
            EnumSet<CryptoMaterial> required ) {
        UUID objectId = objectKey.getObjectId();
        long version = objectKey.getVersion();

        if ( required.contains( CryptoMaterial.CONTENTS ) ) {
            this.objectApi.setObjectContent( objectId, version, ciphertext.getContents() );
        }
        if ( required.contains( CryptoMaterial.SALT ) ) {
            this.objectApi.setObjectSalt( objectId, version, ciphertext.getSalt() );
        }
        if ( required.contains( CryptoMaterial.IV ) ) {
            this.objectApi.setObjectIv( objectId, version, ciphertext.getIv() );
        }
        if ( required.contains( CryptoMaterial.TAG ) ) {
            this.objectApi.setObjectTag( objectId, version, ciphertext.getTag().or( new byte[ 0 ] ) );
        }
    }

    @Override
    public Object getObject( UUID id ) throws IOException, ExecutionException, SecurityConfigurationException {
        // TODO: Cache
        ObjectMetadata objectMetadata = objectApi.getObjectMetadata( id );
        BlockCiphertext ciphertext = getCiphertextUsingMetadata( objectMetadata );
        CryptoService service = loader.get( VersionedObjectKey.fromObjectMetadata( objectMetadata ) ).get();

        byte[] raw = service.decryptBytes( ciphertext );

        return marshaller.fromTypeBytes( new TypedBytes( raw, objectMetadata.getType() ) );
    }

    private BlockCiphertext getCiphertextUsingMetadata( ObjectMetadata metadata ) {
        UUID objectId = metadata.getId();
        long version = metadata.getVersion();

        byte[] contents = objectApi.getObjectContent( objectId, version );
        byte[] iv = objectApi.getObjectIV( objectId, version );
        byte[] salt = objectApi.getObjectSalt( objectId, version );
        byte[] tag = objectApi.getObjectTag( objectId, version );

        return new BlockCiphertext( iv, salt, contents, Optional.<byte[]> absent(), Optional.of( tag ) );
    }

    @Override
    public void deleteMetadataForObjectId( UUID objectId ) {

    }

    @Override
    public void deleteObject( UUID objectId ) {
        objectApi.delete( objectId );
    }

    @Override
    public ObjectMetadata getObjectMetadata( UUID id ) throws ResourceNotFoundException {
        return objectApi.getObjectMetadata( id );
    }

    @Override
    public VersionedObjectKey registerType( Class<?> clazz ) throws IrisException {
        return typeManager.registerType( clazz );
    }

    @Override
    public <T> T getObject( UUID id, Class<T> clazz ) throws ResourceNotFoundException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public <T> T getObject( UUID id, TypeReference<T> ref ) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public UUID storeObject( Object storeable ) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public ObjectMetadataNode getObjects( Set<UUID> objectIds, Map<UUID, Set<LoadLevel>> loadLevelsByTypeId )
            throws ResourceNotFoundException {
        ObjectTreeLoadRequest request = new ObjectTreeLoadRequest( objectIds, loadLevelsByTypeId );
        Map<UUID, ObjectMetadataEncryptedNode> encryptedObjects = objectApi.getObjectsByTypeAndLoadLevel( request );

        for ( UUID id : objectIds ) {
            ObjectMetadata objectMetadata = objectApi.getObjectMetadata( id );
            VersionedObjectKey key = objectApi.getLatestVersionedObjectKey( id );
        }

        return null;
    }

    @Override
    public Set<UUID> getObjectIds() {
        return listingApi.getAllObjectIds( connection.getUserId() );
    }

    @Override
    public Set<UUID> getObjectIds( int offset, int pageSize ) {
        return listingApi.getAllObjectIdsPaged( connection.getUserId(), offset, pageSize );
    }

    @Override
    public Map<Integer, String> getObjectPreview( UUID objectId, List<Integer> locations, int wordRadius )
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException,
            ClassNotFoundException, IOException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Iterable<UUID> getObjectIdsByType( UUID type ) {
        return listingApi.getObjectIdsByType( connection.getUserId(), type );
    }

    @Override
    public Set<UUID> getObjectIdsByType( UUID type, int offset, int pageSize ) {
        return listingApi.getObjectIdsByTypePaged( connection.getUserId(), type, offset, pageSize );
    }

    @Override
    public Object getObject( ObjectMetadata objectMetadata ) throws ResourceNotFoundException, ExecutionException,
            SecurityConfigurationException, IOException {
        UUID objectId = objectMetadata.getId();
        long version = objectMetadata.getVersion();

        Optional<CryptoService> maybeObjectCryptoService = loader.get( new VersionedObjectKey( objectId, version ) );

        if ( maybeObjectCryptoService.isPresent() ) {
            CryptoService objectCryptoService = maybeObjectCryptoService.get();

            byte[] contents = objectApi.getObjectContent( objectId, version );
            byte[] iv = objectApi.getObjectIV( objectId, version );
            byte[] salt = objectApi.getObjectSalt( objectId, version );
            byte[] tag = objectApi.getObjectTag( objectId, version );

            BlockCiphertext ciphertext = new BlockCiphertext(
                    iv,
                    salt,
                    contents,
                    Optional.<byte[]> absent(),
                    Optional.<byte[]> of( tag ) );

            byte[] bytes = objectCryptoService.decryptBytes( ciphertext );
            return marshaller.fromTypeBytes( new TypedBytes( bytes, objectMetadata.getType() ) );
        }
        logger.error( "Unable to find crypto service for object: {}", objectMetadata );
        throw new ResourceNotFoundException( "Unable to find crypto service for object: " + objectMetadata.toString() );
    }

    @Override
    public Map<UUID, String> getStrings( Iterable<UUID> objectIds )
            throws IOException, ExecutionException, SecurityConfigurationException {
        if ( objectIds == null ) {
            return ImmutableMap.of();
        }
        Map<UUID, String> strings = Maps.newHashMapWithExpectedSize( Iterables.size( objectIds ) );
        for ( UUID id : objectIds ) {
            strings.put( id, (String) getObject( id ) );
        }
        return strings;
    }

    @Override
    public VersionedObjectKey storeIndexedString( String s ) throws BadRequestException,
            SecurityConfigurationException, IrisException, ResourceLockedException, ResourceNotFoundException,
            IOException, ExecutionException {
        StorageOptions options = new StorageOptionsBuilder()
                .searchable()
                .storeable()
                .withType( TypeUUIDs.UTF8_STRING )
                .build();
        return storeObject( options, s );
    }

}
