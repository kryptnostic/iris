package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.api.v1.sharing.IndexPair;
import com.kryptnostic.indexing.v1.PaddedMetadata;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.serialization.crypto.Encryptable;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.storage.v1.http.ObjectStorageApi;
import com.kryptnostic.storage.v1.models.EncryptableBlock;
import com.kryptnostic.storage.v1.models.IndexedMetadata;
import com.kryptnostic.storage.v1.models.KryptnosticObject;
import com.kryptnostic.storage.v1.models.ObjectMetadata;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.storage.v1.models.request.PendingObjectRequest;
import com.kryptnostic.storage.v1.models.request.StorageRequest;

/**
 * @author sinaiman
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
    public String uploadObject( StorageRequest req ) throws BadRequestException, SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException {
        String id = req.getObjectId();

        if ( id == null ) {
            PendingObjectRequest pendingRequest = new PendingObjectRequest( req.getType(), req.getParentObjectId()
                    .orNull(), Optional.<Boolean> absent() );
            id = objectApi.createPendingObject( pendingRequest ).getData();
        } else {
            objectApi.createPendingObjectFromExisting( id );
        }

        KryptnosticObject obj = KryptnosticObject.fromIdAndBody( id, req.getObjectBody() );

        Preconditions.checkArgument( !obj.getBody().isEncrypted() );
        String objId = obj.getMetadata().getId();
        // upload the object blocks
        if ( req.isStoreable() ) {
            storeObject( obj );
        }


        if ( req.isSearchable() ) {
            IndexPair indexPair = setupSharing( obj );
            makeObjectSearchable( obj, indexPair.getObjectSearchKey(), indexPair.getObjectAddressMatrix() );
        }

        return objId;
    }

    private void makeObjectSearchable( KryptnosticObject object, byte[] objectSearchKey, byte[] objectAddressMatrix )
            throws IrisException, BadRequestException {
        // index + map tokens for metadata
        Stopwatch watch = Stopwatch.createStarted();
        Set<Metadata> metadata = indexer.index( object.getMetadata().getId(), object.getBody().getData() );
        logger.debug( "[PROFILE] indexer took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        logger.debug( "[PROFILE] {} metadata indexed", metadata.size() );

        watch.reset().start();
        List<MetadataRequest> metadataRequests = prepareMetadata( metadata, objectSearchKey, objectAddressMatrix );
        logger.debug( "[PROFILE] preparing took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        watch.reset().start();
        uploadMetadata( metadataRequests );
        logger.debug( "[PROFILE] uploading metadata took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

    }

    private IndexPair setupSharing( KryptnosticObject object ) throws IrisException {
        Stopwatch watch = Stopwatch.createStarted();
        KryptnosticEngine engine = context.getConnection().getKryptnosticEngine();
        IndexPair splitIndexPair = IndexPair.newFromKryptnosticEngine( engine );
        byte[] indexPair = splitIndexPair.computeIndexPair( engine );
        // byte[] sharingPair = splitIndexPair.computeSharingPair( engine );
        logger.debug( "[PROFILE] generating sharing key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        watch.reset().start();
        context.addIndexPair( object.getMetadata().getId(), indexPair );
        logger.debug( "[PROFILE] submitting bridge key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        return splitIndexPair;
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
    public KryptnosticObject getObject( String id ) throws ResourceNotFoundException {
        return objectApi.getObject( id );
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

    @Override
    public Collection<String> getObjectIds() {
        return objectApi.getObjectIds().getData();
    }

    @Override
    public Collection<String> getObjectIds( int offset, int pageSize ) {
        return objectApi.getObjectIds( offset, pageSize ).getData();
    }

    @Override
    public Collection<String> getObjectIdsByType( String type ) {
        return objectApi.getObjectIdsByType( type ).getData();
    }

    @Override
    public Collection<String> getObjectIdsByType( String type, int offset, int pageSize ) {
        return objectApi.getObjectIdsByType( type, offset, pageSize ).getData();
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
            byte[] objectSearchKey,
            byte[] objectAddressMatrix )
            throws IrisException {

        // create plaintext metadata
        Collection<PaddedMetadata> keyedMetadata = metadataMapper.mapTokensToKeys( metadata,
                objectSearchKey,
                objectAddressMatrix );
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
                metadataIndex.add( new IndexedMetadata( address, encryptedMetadatum, metadatumToEncrypt.getObjectId() ) );
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
    public void deleteMetadata( String id ) {
        metadataApi.deleteAll( new MetadataDeleteRequest( Lists.newArrayList( id ) ) );
    }

    @Override
    public void deleteObject( String id ) {
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
    public ObjectMetadata getObjectMetadata( String id ) throws ResourceNotFoundException {
        return objectApi.getObjectMetadata( id );
    }
}
