package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.api.v1.utils.DocumentFragmentFormatter;
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.MappedMetadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.serialization.crypto.DefaultChunkingStrategy;
import com.kryptnostic.kodex.v1.serialization.crypto.Encryptable;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.MetadataApi;
import com.kryptnostic.storage.v1.http.ObjectApi;
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
    private static final int          PARALLEL_NETWORK_THREADS = 4;
    ListeningExecutorService          exec                     = MoreExecutors.listeningDecorator( Executors
                                                                       .newFixedThreadPool( PARALLEL_NETWORK_THREADS ) );

    /**
     * Server-side
     */
    private final ObjectApi           objectApi;
    private final MetadataApi         metadataApi;
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
            ObjectApi objectApi,
            MetadataApi metadataApi,
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
            id = objectApi.createPendingObject( new PendingObjectRequest( req.getType() ) ).getData();
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
            makeObjectSearchable( obj );
        }

        return objId;
    }

    private void makeObjectSearchable( KryptnosticObject object ) throws IrisException, BadRequestException {
        // index + map tokens for metadata
        Stopwatch watch = Stopwatch.createStarted();
        Set<Metadata> metadata = indexer.index( object.getMetadata().getId(), object.getBody().getData() );
        logger.debug( "[PROFILE] indexer took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        // generate nonce
        EncryptedSearchSharingKey sharingKey = context.generateSharingKey();
        logger.debug( "[PROFILE] generating sharing key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        watch.reset().start();
        context.submitBridgeKeyWithSearchNonce( object.getMetadata().getId(), sharingKey );

        logger.debug( "[PROFILE] submitting bridge key took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        watch.reset().start();
        MetadataRequest metadataRequest = prepareMetadata( metadata, sharingKey );
        uploadMetadata( metadataRequest );
        logger.debug( "[PROFILE] preparing metadata and upload took {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

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
    public String uploadMetadata( MetadataRequest req ) throws BadRequestException {
        return metadataApi.uploadMetadata( req ).getData();
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
    private MetadataRequest prepareMetadata( Set<Metadata> metadata, EncryptedSearchSharingKey sharingKey )
            throws IrisException {

        // create plaintext metadata
        MappedMetadata keyedMetadata = metadataMapper.mapTokensToKeys( metadata, sharingKey );
        logger.debug( "generated plaintext metadata {}", keyedMetadata );

        // encrypt the metadata and format for the server
        Collection<IndexedMetadata> metadataIndex = Lists.newArrayList();
        for ( Map.Entry<BitVector, List<Metadata>> m : keyedMetadata.getMetadataMap().entrySet() ) {
            BitVector key = m.getKey();
            List<Metadata> metadataForKey = m.getValue();

            // encrypt the metadata
            for ( Metadata metadatumToEncrypt : metadataForKey ) {
                Encryptable<Metadata> encryptedMetadatum = new Encryptable<Metadata>(
                        metadatumToEncrypt,
                        metadatumToEncrypt.getObjectId() );
                metadataIndex.add( new IndexedMetadata( key, encryptedMetadatum, metadatumToEncrypt.getObjectId() ) );
            }
        }
        return new MetadataRequest( metadataIndex );
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
            throws SecurityConfigurationException, ExecutionException, ResourceNotFoundException {
        Map<Integer, Integer> offsetsToBlockIndex = DefaultChunkingStrategy.getBlockIndexForByteOffset( locations );

        List<EncryptableBlock> blocks = getObjectBlocks(
                objectId,
                Lists.newArrayList( Sets.newHashSet( offsetsToBlockIndex.values() ) ) );

        Map<Integer, EncryptableBlock> offsetsToBlock = Maps.newHashMap();
        for ( Integer offset : offsetsToBlockIndex.keySet() ) {
            for ( EncryptableBlock block : blocks ) {
                if ( block.getIndex() == offsetsToBlockIndex.get( offset ) ) {
                    offsetsToBlock.put( offset, block );
                    break;
                }
            }
        }

        Map<Integer, String> offsetsToString = Maps.newHashMap();
        for ( Map.Entry<Integer, EncryptableBlock> entry : offsetsToBlock.entrySet() ) {
            offsetsToString.put(
                    entry.getKey(),
                    StringUtils.newStringUtf8( loader.get( objectId ).decryptBytes( entry.getValue().getBlock() ) ) );
        }

        Map<Integer, String> offsetsToPreview = Maps.newHashMap();

        for ( Map.Entry<Integer, String> item : offsetsToString.entrySet() ) {
            Map.Entry<Integer, String> normalizedOffsetPair = Pair.<Integer, String> of( item.getKey()
                    % DefaultChunkingStrategy.BLOCK_LENGTH_IN_BYTES, item.getValue() );
            String preview = DocumentFragmentFormatter.format( normalizedOffsetPair, 2 );
            offsetsToPreview.put( item.getKey(), preview );
        }

        return offsetsToPreview;
    }

    @Override
    public String appendObject( ObjectMetadata objectMetadata, String body ) throws SecurityConfigurationException,
            ExecutionException, ResourceNotFoundException, IrisException, BadRequestException {
        CryptoService crypto = this.context.getConnection().getCryptoServiceLoader().get( objectMetadata.getId() );

        int curNumBlocks = objectMetadata.getNumBlocks();
        BlockCiphertext ciphertext = crypto.encrypt( body.getBytes() );

        EncryptableBlock blockToAppend = new EncryptableBlock( ciphertext, Encryptable.hashFunction.hashBytes(
                ciphertext.getContents() ).asBytes(), curNumBlocks, true, crypto.encrypt( String.class
                .getCanonicalName().getBytes() ), objectMetadata.getChunkingStrategy(), DateTime.now() );

        ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
        String str = null;
        try {
            str = mapper.writeValueAsString( blockToAppend );
        } catch ( JsonProcessingException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        Set<Metadata> metadata = indexer.index( objectMetadata.getId(), body );
        EncryptedSearchPrivateKey privKey = context.getConnection().getEncryptedSearchPrivateKey();
        EncryptedSearchBridgeKey bridgeKey = sharingApi.getEncryptedSearchObjectKey( objectMetadata.getId() )
                .getBridgeKey();

        EncryptedSearchSharingKey encryptedSearchSharingKey = privKey.calculateSharingKey( bridgeKey );
        MetadataRequest mreq = prepareMetadata( metadata, encryptedSearchSharingKey );
        uploadMetadata( mreq );
        return objectApi.appendObject( objectMetadata.getId(), blockToAppend ).getData();
    }

    @Override
    public ObjectMetadata getObjectMetadata( String id ) throws ResourceNotFoundException {
        return objectApi.getObjectMetadata( id );
    }
}
