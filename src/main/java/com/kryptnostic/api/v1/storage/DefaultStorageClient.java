package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
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
import com.kryptnostic.kodex.v1.indexing.metadata.MappedMetadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.serialization.crypto.Encryptable;
import com.kryptnostic.sharing.v1.models.DocumentId;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.DocumentApi;
import com.kryptnostic.storage.v1.http.MetadataApi;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.EncryptableBlock;
import com.kryptnostic.storage.v1.models.IndexedMetadata;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.storage.v1.models.request.StorageRequest;

/**
 * @author sinaiman
 *
 */
public class DefaultStorageClient implements StorageClient {
    private static final Logger       log                      = LoggerFactory.getLogger( StorageClient.class );
    private static final int          PARALLEL_NETWORK_THREADS = 4;
    ListeningExecutorService          exec                     = MoreExecutors.listeningDecorator( Executors
                                                                       .newFixedThreadPool( PARALLEL_NETWORK_THREADS ) );

    /**
     * Server-side
     */
    private final DocumentApi         documentApi;
    private final MetadataApi         metadataApi;

    /**
     * Client-side
     */
    private final KryptnosticContext  context;
    private final MetadataMapper      metadataMapper;
    private final Indexer             indexer;
    private final CryptoServiceLoader loader;

    /**
     * @param context
     * @param documentApi
     * @param metadataApi
     */
    public DefaultStorageClient( KryptnosticContext context, DocumentApi documentApi, MetadataApi metadataApi ) {
        this.context = context;
        this.documentApi = documentApi;
        this.metadataApi = metadataApi;
        this.metadataMapper = new PaddedMetadataMapper( context );
        this.indexer = new SimpleIndexer();
        this.loader = context.getConnection().getCryptoServiceLoader();
    }

    public static class StorageRequestBuilder {
        private String  documentId;
        private String  documentBody;
        private boolean isSearchable;
        private boolean isStoreable;

        public StorageRequestBuilder() {
            documentBody = null;
            documentId = null;
            isSearchable = true;
            isStoreable = true;
        }

        private StorageRequestBuilder clone( StorageRequestBuilder o ) {
            StorageRequestBuilder b = new StorageRequestBuilder();
            b.documentBody = o.documentBody;
            b.documentId = o.documentId;
            b.isSearchable = o.isSearchable;
            b.isStoreable = o.isStoreable;
            return b;
        }

        public StorageRequestBuilder withBody( String documentBody ) {
            StorageRequestBuilder b = clone( this );
            b.documentBody = documentBody;
            return b;
        }

        public StorageRequestBuilder withId( String documentId ) {
            StorageRequestBuilder b = clone( this );
            b.documentId = documentId;
            return b;
        }

        public StorageRequestBuilder searchable() {
            StorageRequestBuilder b = clone( this );
            b.isSearchable = true;
            return b;
        }

        public StorageRequestBuilder storeable() {
            StorageRequestBuilder b = clone( this );
            b.isStoreable = true;
            return b;
        }

        public StorageRequestBuilder notSearchable() {
            StorageRequestBuilder b = clone( this );
            b.isSearchable = false;
            return b;
        }

        public StorageRequestBuilder notStoreable() {
            StorageRequestBuilder b = clone( this );
            b.isStoreable = false;
            return b;
        }

        public StorageRequest build() {
            if ( documentBody == null ) {
                throw new IllegalStateException( "Document body must not be null" );
            }
            if ( !isSearchable && !isStoreable ) {
                throw new IllegalStateException( "Not searchable or storeable, so no-op" );
            }
            return new StorageRequest( documentId, documentBody, isSearchable, isStoreable );
        }
    }

    @Override
    public String uploadDocument( StorageRequest req ) throws BadRequestException, SecurityConfigurationException,
            IrisException, ResourceLockedException, ResourceNotFoundException {
        String documentId = req.getDocumentId();

        if ( documentId == null ) {
            documentId = documentApi.createPendingDocument().getData().getDocumentId();
        } else {
            documentApi.createPendingDocument( documentId );
        }

        Document document = Document.fromIdAndBody( documentId, req.getDocumentBody() );

        Preconditions.checkArgument( !document.getBody().isEncrypted() );
        String docId = document.getMetadata().getId();
        // upload the document blocks
        if ( req.isStoreable() ) {
            storeDocument( document );
        }

        if ( req.isSearchable() ) {
            makeDocumentSearchable( document );
        }

        return docId;
    }

    private void makeDocumentSearchable( Document document ) throws IrisException, BadRequestException {
        // index + map tokens for metadata
        Set<Metadata> metadata = indexer.index( document.getMetadata().getId(), document.getBody().getData() );

        // generate nonce
        BitVector searchNonce = context.generateSearchNonce();
        EncryptedSearchSharingKey sharingKey = context.generateSharingKey();

        context.submitBridgeKeyWithSearchNonce(
                new DocumentId( document.getMetadata().getId() ),
                sharingKey,
                searchNonce );

        MetadataRequest metadataRequest = prepareMetadata( metadata, searchNonce, sharingKey );
        uploadMetadata( metadataRequest );

    }

    private void storeDocument( Document document ) throws SecurityConfigurationException, IrisException {
        try {
            document = document.encrypt( loader );
        } catch ( ClassNotFoundException | IOException e ) {
            throw new SecurityConfigurationException( e );
        }
        submitBlocksToServer( document );
    }

    @Override
    public Document getDocument( DocumentId id ) throws ResourceNotFoundException {
        return documentApi.getDocument( id.getDocumentId() ).getData();
    }

    @Override
    public String uploadMetadata( MetadataRequest req ) throws BadRequestException {
        return metadataApi.uploadMetadata( req ).getData();
    }

    @Override
    public Collection<DocumentId> getDocumentIds() {
        return documentApi.getDocumentIds().getData();
    }

    // @Override
    // // TODO: calculate fragments to request client side
    // public Map<Integer, String> getDocumentFragments( DocumentId id, List<Integer> offsets, int characterWindow )
    // throws ResourceNotFoundException, SecurityConfigurationException, IrisException {
    // Map<Integer, String> plain = Maps.newHashMap();
    //
    // DocumentFragmentRequest fragmentRequest = new DocumentFragmentRequest( offsets, characterWindow );
    //
    // Map<Integer, List<EncryptableBlock>> encrypted = documentApi.getDocumentFragments(
    // id.getDocumentId(),
    // fragmentRequest ).getData();
    //
    // for ( Entry<Integer, List<EncryptableBlock>> e : encrypted.entrySet() ) {
    // String preview = "";
    // for ( EncryptableBlock block : e.getValue() ) {
    // try {
    // preview += StringUtils.newStringUtf8( loader.get( id ).decryptBytes( block.getBlock() ) );
    // } catch ( ExecutionException e1 ) {
    // throw new IrisException( e1 );
    // }
    // }
    // plain.put( e.getKey(), preview );
    // }
    // return plain;
    // }

    /**
     * Maps all metadata to an index that the server can compute when searching
     * 
     * @param metadata
     * @return
     * @throws IrisException
     */
    private MetadataRequest prepareMetadata(
            Set<Metadata> metadata,
            BitVector searchNonce,
            EncryptedSearchSharingKey sharingKey ) throws IrisException {

        // create plaintext metadata
        MappedMetadata keyedMetadata = metadataMapper.mapTokensToKeys( metadata, searchNonce, sharingKey );
        log.debug( "generated plaintext metadata {}", keyedMetadata );

        // encrypt the metadata and format for the server
        Collection<IndexedMetadata> metadataIndex = Lists.newArrayList();
        for ( Map.Entry<BitVector, List<Metadata>> m : keyedMetadata.getMetadataMap().entrySet() ) {
            BitVector key = m.getKey();
            List<Metadata> metadataForKey = m.getValue();

            // encrypt the metadata
            for ( Metadata metadatumToEncrypt : metadataForKey ) {
                Encryptable<Metadata> encryptedMetadatum = new Encryptable<Metadata>( metadatumToEncrypt );
                metadataIndex.add( new IndexedMetadata( key, encryptedMetadatum, metadatumToEncrypt.getDocumentId() ) );
            }
        }
        return new MetadataRequest( metadataIndex );
    }

    /**
     * Submit blocks in parallel
     * 
     * @param documentId
     * @param blocks
     * @throws IrisException
     */
    private void submitBlocksToServer( final Document document ) throws IrisException {
        Preconditions.checkNotNull( document.getBody().getEncryptedData() );
        final String documentId = document.getMetadata().getId();
        try {
            Futures.allAsList(
                    Iterables.transform(
                            Arrays.asList( document.getBody().getEncryptedData() ),
                            new Function<EncryptableBlock, ListenableFuture<?>>() {
                                @Override
                                public ListenableFuture<?> apply( final EncryptableBlock input ) {
                                    return exec.submit( new Runnable() {
                                        @Override
                                        public void run() {
                                            // push the block to the server
                                            try {
                                                documentApi.updateDocument( documentId, input );
                                            } catch (
                                                    ResourceNotFoundException
                                                    | ResourceNotLockedException
                                                    | BadRequestException e ) {
                                                log.error( "Failed to uploaded block. Should probably add a retry here!" );
                                            }
                                            log.info(
                                                    "Document blocked uploaded completed for document {} and block {}",
                                                    documentId,
                                                    input.getIndex() );
                                        }
                                    } );
                                }
                            } ) ).get();
        } catch ( InterruptedException | ExecutionException e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public void deleteMetadata( DocumentId id ) {
        metadataApi.deleteAll( new MetadataDeleteRequest( Lists.newArrayList( id ) ) );
    }

    @Override
    public void deleteDocument( DocumentId id ) {
        documentApi.delete( id.getDocumentId() );
    }

    @Override
    public List<Document> getDocuments( List<DocumentId> ids ) throws ResourceNotFoundException {
        return documentApi.getDocuments( ids ).getData();
    }
}
