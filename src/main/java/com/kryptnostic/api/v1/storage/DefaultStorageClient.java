package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;

import org.apache.commons.codec.binary.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
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
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.MappedMetadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.models.AesEncryptable;
import com.kryptnostic.kodex.v1.models.Encryptable;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.sharing.v1.models.DocumentId;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.DocumentApi;
import com.kryptnostic.storage.v1.http.MetadataApi;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.DocumentBlock;
import com.kryptnostic.storage.v1.models.DocumentMetadata;
import com.kryptnostic.storage.v1.models.IndexedMetadata;
import com.kryptnostic.storage.v1.models.request.DocumentCreationRequest;
import com.kryptnostic.storage.v1.models.request.DocumentFragmentRequest;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class DefaultStorageClient implements StorageClient {
    private static final Logger         log                      = LoggerFactory.getLogger( StorageClient.class );
    private static final int            PARALLEL_NETWORK_THREADS = 4;
    ListeningExecutorService            exec                     = MoreExecutors
                                                                         .listeningDecorator( Executors
                                                                                 .newFixedThreadPool( PARALLEL_NETWORK_THREADS ) );

    /**
     * Server-side
     */
    private final DocumentApi           documentApi;
    private final MetadataApi           metadataApi;

    /**
     * Client-side
     */
    private final KryptnosticContext    context;
    private final MetadataMapper        metadataMapper;
    private final Indexer               indexer;
    private final KryptnosticConnection securityService;
    private final CryptoServiceLoader   loader;

    public DefaultStorageClient( KryptnosticContext context, DocumentApi documentApi, MetadataApi metadataApi ) {
        this.context = context;
        this.documentApi = documentApi;
        this.metadataApi = metadataApi;
        this.securityService = context.getConnection();
        this.metadataMapper = new PaddedMetadataMapper( context );
        this.indexer = new SimpleIndexer();
        this.loader = context.getConnection().getCryptoServiceLoader();
    }

    @Override
    public String uploadDocumentWithMetadata( String documentBody ) throws SecurityConfigurationException,
            IrisException, BadRequestException, JsonProcessingException {
        // Generate the encrypted encryptable
        Encryptable<String> body = new AesEncryptable<String>( documentBody );

        // Create a new pending document on the server
        DocumentCreationRequest documentRequest = new DocumentCreationRequest( body.getBlockCount() );
        DocumentId documentId = documentApi.createPendingDocument( documentRequest ).getData();

        // Update this pending document with the necessary blocks to complete the upload
        // Also make sure metadata is uploaded
        return updateDocumentWithMetadata( documentId, documentBody, body );
    }

    @Override
    public String uploadDocumentWithoutMetadata( String documentBody ) throws BadRequestException,
            SecurityConfigurationException, IrisException, JsonProcessingException {
        Encryptable<String> body = new AesEncryptable<String>( documentBody );

        DocumentCreationRequest documentRequest = new DocumentCreationRequest( body.getBlockCount() );
        String documentId = documentApi.createPendingDocument( documentRequest ).getData().getDocumentId();
        return updateDocumentWithoutMetadata( documentId, body );
    }

    @Override
    public String updateDocumentWithMetadata( String documentId, String documentBody, Encryptable<String> body )
            throws ResourceNotFoundException, BadRequestException, SecurityConfigurationException, IrisException {
        return updateDocumentWithMetadata( documentId, documentBody, body );
    }

    /**
     * All the other update/uploadDocument functions are syntactic sugar for this method, which actually does all the
     * work to update a document
     * 
     * This chunks up the blocks and uploads them in parallel
     * 
     * @param documentId
     * @param documentBody
     * @return
     * @throws BadRequestException
     * @throws SecurityConfigurationException
     * @throws IrisException
     */
    @Override
    public String updateDocumentWithoutMetadata( String documentId, Encryptable<String> documentBody )
            throws BadRequestException, SecurityConfigurationException, IrisException {
        DocumentId docId = new DocumentId( documentId );
        Document doc = generateDocument( docId, documentBody );
        submitBlocksToServer( docId, doc.getBlocks() );
        return documentId;
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

    @Override
    public Map<Integer, String> getDocumentFragments( DocumentId id, List<Integer> offsets, int characterWindow )
            throws ResourceNotFoundException, SecurityConfigurationException, IrisException {
        Map<Integer, String> plain = Maps.newHashMap();

        DocumentFragmentRequest fragmentRequest = new DocumentFragmentRequest( offsets, characterWindow );

        Map<Integer, List<DocumentBlock>> encrypted = documentApi.getDocumentFragments(
                id.getDocumentId(),
                fragmentRequest ).getData();

        for ( Entry<Integer, List<DocumentBlock>> e : encrypted.entrySet() ) {
            String preview = "";
            for ( DocumentBlock block : e.getValue() ) {
                try {
                    preview += StringUtils.newStringUtf8( loader.get( id ).decryptBytes( block.getBlock() ) );
                } catch ( ExecutionException e1 ) {
                    throw new IrisException( e1 );
                }
            }
            plain.put( e.getKey(), preview );
        }
        return plain;
    }

    /**
     * Updates the document and also uploads the metadata. All other methods are syntactic sugar that lead to this
     * method
     * 
     * @param documentId
     * @param documentBody
     * @param verified
     * @return
     * @throws BadRequestException
     * @throws SecurityConfigurationException
     * @throws IrisException
     */
    private String updateDocumentWithMetadata( DocumentId documentId, String documentBody, Encryptable<String> body )
            throws BadRequestException, SecurityConfigurationException, IrisException {
        // upload the document blocks
        updateDocumentWithoutMetadata( documentId.getDocumentId(), body );

        // index + map tokens for metadata
        Set<Metadata> metadata = indexer.index( documentId.getDocumentId(), documentBody );

        // generate nonce
        BitVector searchNonce = context.generateSearchNonce();
        EncryptedSearchSharingKey sharingKey = context.generateSharingKey();

        context.submitBridgeKeyWithSearchNonce( documentId, sharingKey, searchNonce );

        MetadataRequest metadataRequest = prepareMetadata( metadata, searchNonce, sharingKey );
        uploadMetadata( metadataRequest );

        return documentId.getDocumentId();
    }

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
                Encryptable<Metadata> encryptedMetadatum = new AesEncryptable<Metadata>( metadatumToEncrypt );
                metadataIndex.add( new IndexedMetadata( key, encryptedMetadatum, metadatumToEncrypt.getDocumentId() ) );
            }
        }
        return new MetadataRequest( metadataIndex );
    }

    /**
     * Chunk up a document into blocks
     * 
     * @param documentId
     * @param documentBody
     * @param verifiedStringBlocks
     * @return
     * @throws IrisException
     * @throws SecurityConfigurationException
     */
    private Document generateDocument( DocumentId documentId, Encryptable<String> body ) throws IrisException,
            SecurityConfigurationException {
        try {
            body.encrypt( loader );
            return new Document(
                    new DocumentMetadata( documentId.getDocumentId(), body.getBlockCount() ),
                    body.getEncryptedData() );
        } catch ( IOException e ) {
            throw new IrisException( e );
        }
    }

    /**
     * Submit blocks in parallel
     * 
     * @param documentId
     * @param blocks
     * @throws IrisException
     */
    private void submitBlocksToServer( final DocumentId documentId, final DocumentBlock[] blocks ) throws IrisException {
        try {
            Futures.allAsList(
                    Iterables.transform( Arrays.asList( blocks ), new Function<DocumentBlock, ListenableFuture<?>>() {
                        @Override
                        public ListenableFuture<?> apply( final DocumentBlock input ) {
                            return exec.submit( new Runnable() {
                                @Override
                                public void run() {
                                    // push the block to the server
                                    try {
                                        documentApi.updateDocument( documentId.getDocumentId(), input );
                                    } catch (
                                            ResourceNotFoundException
                                            | ResourceNotLockedException
                                            | BadRequestException e ) {
                                        log.error( "Failed to uploaded block. Should probably add a retry here!" );
                                    }
                                    log.info(
                                            "Document blocked uploaded completed for document {} and block {}",
                                            documentId.getDocumentId(),
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
