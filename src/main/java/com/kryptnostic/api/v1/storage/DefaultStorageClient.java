package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.storage.v1.models.EncryptableBlock;
import com.kryptnostic.storage.v1.models.KryptnosticObject;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.indexing.IndexMetadata;
import com.kryptnostic.v2.indexing.Indexer;
import com.kryptnostic.v2.indexing.PaddedMetadataMapper;
import com.kryptnostic.v2.indexing.SimpleIndexer;
import com.kryptnostic.v2.indexing.metadata.Metadata;
import com.kryptnostic.v2.indexing.metadata.MetadataMapper;
import com.kryptnostic.v2.indexing.metadata.MetadataRequest;
import com.kryptnostic.v2.marshalling.JsonJacksonMarshallingService;
import com.kryptnostic.v2.marshalling.MarshallingService;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;
import com.kryptnostic.v2.storage.models.LoadLevel;
import com.kryptnostic.v2.storage.models.ObjectMetadata;
import com.kryptnostic.v2.storage.models.ObjectMetadataEncryptedNode;
import com.kryptnostic.v2.storage.models.ObjectMetadataNode;
import com.kryptnostic.v2.storage.models.ObjectTreeLoadRequest;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;
import com.kryptnostic.v2.types.TypedBytes;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultStorageClient implements StorageClient {
    public static final byte[]        ZERO_LENGTH_BYTE_ARRAY   = new byte[ 0 ];
    private static final Logger       logger                   = LoggerFactory.getLogger( StorageClient.class );
    private static final int          PARALLEL_NETWORK_THREADS = 16;
    private static final int          METADATA_BATCH_SIZE      = 500;
    ExecutorService                   exec                     = Executors
                                                                       .newFixedThreadPool( PARALLEL_NETWORK_THREADS );

    /**
     * Server-side
     */
    private final ObjectStorageApi    objectApi;
    private final MetadataStorageApi  metadataApi;
    private final SharingApi          sharingApi;

    /**
     * Client-side
     */
    private final MetadataMapper      metadataMapper;
    private final Indexer             indexer;
    private final CryptoServiceLoader loader;
    private final MarshallingService  marshaller;

    /**
     * @param context
     * @param objectApi
     * @param metadataApi
     * @throws ResourceNotFoundException
     * @throws ClassNotFoundException
     */
    public DefaultStorageClient(
            KryptnosticConnection connection,
            ObjectStorageApi objectApi,
            MetadataStorageApi metadataApi,
            SharingApi sharingApi ) throws ClassNotFoundException, ResourceNotFoundException {
        this.objectApi = objectApi;
        this.metadataApi = metadataApi;
        this.sharingApi = sharingApi;
        this.metadataMapper = new PaddedMetadataMapper( context );
        this.indexer = new SimpleIndexer();
        this.marshaller = new JsonJacksonMarshallingService( this );
        this.loader = Preconditions.checkNotNull(
                connection.getCryptoServiceLoader(),
                "CryptoServiceLoader from KryptnosticConnection cannot be null." );
    }

    @Override
    public VersionedObjectKey storeObject( StorageOptions req, Object storeable ) throws BadRequestException,
            SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException, IOException, ExecutionException {

        VersionedObjectKey objectKey = objectApi.createObject( req.toCreateObjectRequest() );
        TypedBytes bytes = marshaller.toTypedBytes( storeable );

        Optional<CryptoService> maybeObjectCryptoService = loader.get( objectKey );
        CryptoService objectCryptoService;

        if ( maybeObjectCryptoService.isPresent() ) {
            objectCryptoService = maybeObjectCryptoService.get();
        } else {
            // TODO: Centralize error messages somewhere so that we can manage error messages and resources.
            logger.error( "Unable to get or create an object crypto service for object: {} ", objectKey );
            throw new ResourceNotFoundException( "Unable to get or create an object crypto service for object "
                    + objectKey.toString() );
        }

        if ( req.isStoreable() ) {
            // TODO: Add BLOCK chunking
            BlockCiphertext ciphertext = objectCryptoService.encrypt( bytes.getBytes() );

            storeObject( objectKey, ciphertext );
        }

        if ( req.isSearchable() && ( storeable instanceof String ) ) {
            // Setting up sharing is only required if object is searchable.
            byte[] objectIndexPair = provisionSearchPairAndReturnCorrespondingIndexPair( objectKey );
            makeObjectSearchable( objectKey, (String) storeable, objectIndexPair );
        }

        return objectKey;
    }

    private void makeObjectSearchable( VersionedObjectKey key, String data, byte[] objectIndexPair )
            throws IrisException, BadRequestException {
        // index + map tokens for metadata
        Stopwatch watch = Stopwatch.createStarted();
        Set<Metadata> metadata = indexer.index( key, data );
        logger.debug( "[PROFILE] indexer took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        logger.debug( "[PROFILE] {} metadata indexed", metadata.size() );

        watch.reset().start();
        List<MetadataRequest> metadataRequests = prepareMetadata( metadata, objectIndexPair );
        logger.debug( "[PROFILE] preparing took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        watch.reset().start();
        uploadMetadata( metadataRequests );
        logger.debug( "[PROFILE] uploading metadata took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

    }

    private byte[] provisionSearchPairAndReturnCorrespondingIndexPair( VersionedObjectKey key ) throws IrisException {
        KryptnosticEngine engine = context.getConnection().getKryptnosticEngine();

        Stopwatch watch = Stopwatch.createStarted();
        byte[] objectIndexPair = engine.getObjectIndexPair();
        byte[] objectSearchPair = engine.getObjectSearchPairFromObjectIndexPair( objectIndexPair );
        logger.debug( "[PROFILE] generating sharing key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        // TODO: Centralize these lengths in KryptnosticEngine
        Preconditions.checkState( objectSearchPair.length == KryptnosticEngine.SEARCH_PAIR_LENGTH,
                "Search pair must be 2080 bytes." );
        Preconditions.checkState( objectIndexPair.length == KryptnosticEngine.INDEX_PAIR_LENGTH,
                "Index pair must be 2064 bytes." );

        watch.reset().start();
        context.addIndexPair( key, new ObjectSearchPair( objectSearchPair ) );
        logger.debug( "[PROFILE] submitting bridge key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        return objectIndexPair;
    }

    private void storeObject( VersionedObjectKey objectKey, BlockCiphertext ciphertext )
            throws SecurityConfigurationException, IrisException {
        UUID objectId = objectKey.getObjectId();
        long version = objectKey.getVersion();

        this.objectApi.setObjectContent( objectId, version, ciphertext.getContents() );
        this.objectApi.setObjectIv( objectId, version, ciphertext.getIv() );
        this.objectApi.setObjectSalt( objectId, version, ciphertext.getSalt() );
        this.objectApi.setObjectTag( objectId, version, ciphertext.getTag().or( ZERO_LENGTH_BYTE_ARRAY ) );
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
    public void uploadMetadata( List<MetadataRequest> requests ) throws BadRequestException {
        logger.debug( "Starting metadata upload of {} batches of max size {}", requests.size(), METADATA_BATCH_SIZE );
        List<Future<?>> tasks = Lists.newArrayList();
        final AtomicInteger remaining = new AtomicInteger( requests.size() );
        for ( final MetadataRequest request : requests ) {
            tasks.add( exec.submit( new Runnable() {

                @Override
                public void run() {
                    Stopwatch watch = Stopwatch.createStarted();
                    try {
                        metadataApi.uploadMetadata( request ).getData();
                    } catch ( BadRequestException e ) {
                        logger.error( "Metadata upload failed", e );
                    }
                    logger.debug(
                            "[PROFILE] uploading metadata batch of size {} took {} ms. {} Remaining batches",
                            request.getMetadata().size(),
                            watch.elapsed( TimeUnit.MILLISECONDS ),
                            remaining.decrementAndGet() );
                }

            } ) );
        }

        for ( Future<?> task : tasks ) {
            try {
                task.get();
            } catch ( InterruptedException e ) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            } catch ( ExecutionException e ) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    /**
     * Maps all metadata to an index that the server can compute when searching
     *
     * @param metadata
     * @return
     * @throws IrisException
     */
    private List<MetadataRequest> prepareMetadata(
            Set<Metadata> metadata,
            byte[] objectIndexPair )
            throws IrisException {

        // create plaintext metadata
        Map<ByteBuffer, List<Metadata>> mappedMetadata = metadataMapper.mapTokensToKeys( metadata,
                objectIndexPair );
        // logger.debug( "generated plaintext metadata {}", keyedMetadata );

        // encrypt the metadata and format for the server
        Collection<IndexMetadata> metadataIndex = Lists.newArrayListWithExpectedSize( METADATA_BATCH_SIZE );
        List<MetadataRequest> requests = Lists
                .newArrayListWithExpectedSize( mappedMetadata.size() / METADATA_BATCH_SIZE );
        for ( Entry<ByteBuffer, List<Metadata>> pm : mappedMetadata.entrySet() ) {
            byte[] address = pm.getKey().array();
            List<Metadata> metadataForKey = pm.getValue();

            // encrypt the metadata
            for ( Metadata metadatumToEncrypt : metadataForKey ) {
                StorageOptions options = new StorageOptionBuilder()
                        .notSearchable()
                        .storeable()
                        .inheritCryptoService()
                        .inheritOwner()
                        .build();
                VersionedObjectKey metadataObjectKey;
                try {
                    metadataObjectKey = storeObject( options, metadatumToEncrypt );
                } catch (
                        BadRequestException
                        | SecurityConfigurationException
                        | ResourceLockedException
                        | ResourceNotFoundException
                        | IOException
                        | ExecutionException e ) {
                    logger.error( "Failed to store metadatum. ", e );
                    throw new IrisException( e );
                }

                metadataIndex
                        .add( new IndexMetadata( address, metadataObjectKey, metadatumToEncrypt.getObjectKey() ) );
                if ( metadataIndex.size() == METADATA_BATCH_SIZE ) {
                    requests.add( new MetadataRequest( metadataIndex ) );
                    metadataIndex = Lists.newArrayList();
                }
            }

        }
        if ( !metadataIndex.isEmpty() ) {
            requests.add( new MetadataRequest( metadataIndex ) );
        }

        return requests;
    }

    /**
     * Submit blocks in parallel
     *
     * @param objectId
     * @param blocks
     * @throws IrisException
     */
    private void submitBlocksToServer( final KryptnosticObject obj ) throws IrisException {
        Preconditions.checkNotNull( obj.getBody().getEncryptedData() );
        final String objectId = obj.getMetadata().getId();
        for ( EncryptableBlock input : obj.getBody().getEncryptedData() ) {
            try {
                objectApi.updateObject( objectId, input );
            } catch ( ResourceNotFoundException | ResourceNotLockedException | BadRequestException e ) {
                logger.error( "Failed to uploaded block. Should probably add a retry here!" );
            }
            logger.info( "Object block upload completed for object {} and block {}", objectId, input.getIndex() );
        }
    }

    @Override
    public void deleteMetadata( UUID id ) {
        metadataApi.deleteAll( new MetadataDeleteRequest( ImmutableSet.of( id ) ) );
    }

    @Override
    public void deleteObject( UUID id ) {
        objectApi.delete( id, version )( id );
    }

    @Override
    public ObjectMetadata getObjectMetadata( UUID id ) throws ResourceNotFoundException {
        return objectApi.getObjectMetadata( id );
    }

    @Override
    public UUID registerType( Class<?> clazz ) {
        // TODO Auto-generated method stub
        return null;
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
    public ObjectMetadataNode getObjects( Set<UUID> objectIds, Map<UUID, LoadLevel> loadLevelsByTypeId )
            throws ResourceNotFoundException {
        ObjectTreeLoadRequest request = new ObjectTreeLoadRequest( objectIds, loadLevelsByTypeId );
        Map<UUID, ObjectMetadataEncryptedNode> encryptedObjects = objectApi.getObjectsByTypeAndLoadLevel( request );

        for ( UUID id : objectIds ) {
            ObjectMetadata objectMetadata = objectApi.getObjectMetadata( id );
            VersionedObjectKey key = objectApi.getVersionedObjectKey( id );
            // objects.put( key, objectApi.getObjectMetadata( id ) );
        }

        return null;
    }

    @Override
    public Set<UUID> getObjectIds() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<UUID> getObjectIds( int offset, int pageSize ) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<Integer, String> getObjectPreview( UUID objectId, List<Integer> locations, int wordRadius )
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException,
            ClassNotFoundException, IOException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<UUID> getObjectIdsByType( UUID type ) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Set<UUID> getObjectIdsByType( UUID type, int offset, int pageSize ) {
        // TODO Auto-generated method stub
        return null;
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
    public Map<UUID, String> getStrings( Set<UUID> objectIds ) {
        // TODO Auto-generated method stub
        return null;
    }

}
