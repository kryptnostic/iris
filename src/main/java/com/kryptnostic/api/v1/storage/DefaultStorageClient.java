package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
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
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.indexing.v1.PaddedMetadata;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.serialization.crypto.Encryptable;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.storage.v1.models.EncryptableBlock;
import com.kryptnostic.storage.v1.models.IndexedMetadata;
import com.kryptnostic.storage.v1.models.KryptnosticObject;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.storage.v1.models.request.PendingObjectRequest;
import com.kryptnostic.storage.v2.http.ObjectStorageApi;
import com.kryptnostic.storage.v2.models.ObjectMetadata;
import com.kryptnostic.storage.v2.models.VersionedObjectKey;
import com.kryptnostic.v2.indexing.Indexer;
import com.kryptnostic.v2.indexing.SimpleIndexer;
import com.kryptnostic.v2.indexing.metadata.Metadata;
import com.kryptnostic.v2.types.MarshallingService;
import com.kryptnostic.v2.types.TypedBytes;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultStorageClient implements StorageClient {
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
    private final KryptnosticContext  context;
    private final MetadataMapper      metadataMapper;
    private final Indexer             indexer;
    private final CryptoServiceLoader loader;
    private final MarshallingService  marshaller;

    /**
     * @param context
     * @param objectApi
     * @param metadataApi
     */
    public DefaultStorageClient(
            KryptnosticContext context,
            ObjectStorageApi objectApi,
            MetadataStorageApi metadataApi,
            SharingApi sharingApi ) {
        this.context = context;
        this.objectApi = objectApi;
        this.metadataApi = metadataApi;
        this.sharingApi = sharingApi;
        this.metadataMapper = new PaddedMetadataMapper( context );
        this.indexer = new SimpleIndexer();
        this.loader = Preconditions.checkNotNull(
                context.getConnection().getCryptoServiceLoader(),
                "CryptoServiceLoader from KryptnosticConnection cannot be null." );
    }

    @Override
    public UUID storeObject( StorageOptions req, Object storeable ) throws BadRequestException, SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException {
        
        VersionedObjectKey objectId = objectApi.createObject( req.toCreateObjectRequest() );
        
        TypedBytes bytes = marshaller.toTypedBytes( storeable );
        BlockCiphertext ciphertext = loader.get( objectId.getObjectId() ).;
           
        
        KryptnosticObject obj = KryptnosticObject.fromIdAndBody( id, req.getObjectBody() );

        Preconditions.checkArgument( !obj.getBody().isEncrypted() );
        String objId = obj.getMetadata().getId();
        // upload the object blocks
        if ( req.isStoreable() ) {
            storeObject( obj );
        }

        if ( req.isSearchable() ) {
            // Setting up sharing is only required if object is searchable.
            byte[] objectIndexPair = provisionSearchPairAndReturnCorrespondingIndexPair( obj );
            makeObjectSearchable( obj, objectIndexPair );
        }

        return objId;
    }

    private void makeObjectSearchable( KryptnosticObject object, byte[] objectIndexPair )
            throws IrisException, BadRequestException {
        // index + map tokens for metadata
        Stopwatch watch = Stopwatch.createStarted();
        Set<Metadata> metadata = indexer.index( object.getMetadata().getId(), object.getBody().getData() );
        logger.debug( "[PROFILE] indexer took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        logger.debug( "[PROFILE] {} metadata indexed", metadata.size() );

        watch.reset().start();
        List<MetadataRequest> metadataRequests = prepareMetadata( metadata, objectIndexPair );
        logger.debug( "[PROFILE] preparing took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        watch.reset().start();
        uploadMetadata( metadataRequests );
        logger.debug( "[PROFILE] uploading metadata took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

    }

    private byte[] provisionSearchPairAndReturnCorrespondingIndexPair( KryptnosticObject object ) throws IrisException {
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
        context.addIndexPair( object.getMetadata().getId(), new ObjectSearchPair( objectSearchPair ) );
        logger.debug( "[PROFILE] submitting bridge key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        return objectIndexPair;
    }

    private void storeObject( KryptnosticObject object ) throws SecurityConfigurationException, IrisException {
        try {
            object = object.encrypt( loader );
        } catch ( ClassNotFoundException | IOException e ) {
            throw new SecurityConfigurationException( e );
        }
        submitBlocksToServer( object );
    }

    @Override
    public Object getObject( UUID id ) throws ResourceNotFoundException {

        byte[] contents = objectApi.getObjectBlockCiphertextContent( objectId, version );
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
        Collection<PaddedMetadata> keyedMetadata = metadataMapper.mapTokensToKeys( metadata,
                objectIndexPair );
        // logger.debug( "generated plaintext metadata {}", keyedMetadata );

        // encrypt the metadata and format for the server
        Collection<IndexedMetadata> metadataIndex = Lists.newArrayListWithExpectedSize( METADATA_BATCH_SIZE );
        List<MetadataRequest> requests = Lists
                .newArrayListWithExpectedSize( keyedMetadata.size() / METADATA_BATCH_SIZE );
        for ( PaddedMetadata pm : keyedMetadata ) {
            byte[] address = pm.getAddress();
            List<Metadata> metadataForKey = pm.getMetadata();

            // encrypt the metadata
            for ( Metadata metadatumToEncrypt : metadataForKey ) {
                Encryptable<Metadata> encryptedMetadatum = new Encryptable<Metadata>(
                        metadatumToEncrypt,
                        metadatumToEncrypt.getObjectId() );
                metadataIndex
                        .add( new IndexedMetadata( address, encryptedMetadatum, metadatumToEncrypt.getObjectId() ) );
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
        metadataApi.deleteAll( new MetadataDeleteRequest( Lists.newArrayList( id ) ) );
    }

    @Override
    public void deleteObject( UUID id ) {
        sharingApi.removeIncomingShares( id );
        objectApi.delete( id );
    }

    @Override
    public List<KryptnosticObject> getObjects( List<String> ids ) throws ResourceNotFoundException {
        return objectApi.getObjects( ids ).getData();
    }

    @Override
    public List<EncryptableBlock> getObjectBlocks( String id, List<Integer> indices ) throws ResourceNotFoundException {
        return objectApi.getObjectBlocks( id, indices ).getData();
    }

    @Override
    public Map<Integer, String> getObjectPreview( String objectId, List<Integer> locations, int wordRadius )
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException,
            ClassNotFoundException, IOException {
        KryptnosticObject obj = getObject( objectId );

        String body = obj.getBody().decrypt( this.loader ).getData();
        Map<Integer, String> frags = Maps.newHashMap();
        for ( Integer index : locations ) {
            int backSpaces = 0;
            int backIndex = index;
            for ( ; backIndex > 0; backIndex-- ) {
                if ( new String( body.charAt( backIndex ) + "" ).matches( "\\s" ) ) {
                    backSpaces++;
                    if ( backSpaces > wordRadius ) {
                        if ( backIndex > 0 ) {
                            backIndex++;
                        }
                        break;
                    }
                }
            }

            int frontSpaces = 0;
            int frontIndex = index;
            for ( ; frontIndex < body.length(); frontIndex++ ) {
                if ( new String( body.charAt( frontIndex ) + "" ).matches( "\\s" ) ) {
                    frontSpaces++;
                    if ( frontSpaces > wordRadius ) {
                        if ( frontIndex < body.length() ) {
                            // frontIndex--;
                        }
                        break;
                    }
                }
            }
            frags.put( index, body.substring( backIndex, frontIndex ) );
        }
        return frags;
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
    public Map<UUID, ?> getObjects( List<UUID> ids ) throws ResourceNotFoundException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void deleteObject( UUID id ) {
        // TODO Auto-generated method stub

    }

    @Override
    public Collection<UUID> getObjectIds() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<UUID> getObjectIds( int offset, int pageSize ) {
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
    public Collection<UUID> getObjectIdsByType( UUID type ) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Collection<UUID> getObjectIdsByType( UUID type, int offset, int pageSize ) {
        // TODO Auto-generated method stub
        return null;
    }
}
