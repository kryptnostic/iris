package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.MetadataMapper;
import com.kryptnostic.kodex.v1.indexing.metadata.MappedMetadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.models.AesEncryptable;
import com.kryptnostic.kodex.v1.models.Encryptable;
import com.kryptnostic.kodex.v1.models.utils.AesEncryptableUtils;
import com.kryptnostic.kodex.v1.models.utils.AesEncryptableUtils.VerifiedString;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.sharing.v1.models.DocumentId;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.DocumentApi;
import com.kryptnostic.storage.v1.http.MetadataApi;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.DocumentBlock;
import com.kryptnostic.storage.v1.models.IndexedMetadata;
import com.kryptnostic.storage.v1.models.request.DocumentCreationRequest;
import com.kryptnostic.storage.v1.models.request.DocumentFragmentRequest;
import com.kryptnostic.storage.v1.models.request.MetadataDeleteRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class DefaultStorageClient implements StorageClient {
    private static final Logger         log                      = LoggerFactory.getLogger( StorageClient.class );

    private static final int            PARALLEL_NETWORK_THREADS = 4;

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
    private final Kodex<String>         kodex;

    public DefaultStorageClient( KryptnosticContext context, DocumentApi documentApi, MetadataApi metadataApi ) {
        this.context = context;
        this.documentApi = documentApi;
        this.metadataApi = metadataApi;
        this.securityService = context.getConnection();
        this.metadataMapper = new PaddedMetadataMapper( context );
        this.indexer = new SimpleIndexer();
        this.kodex = context.getConnection().getKodex();
    }

    @Override
    public String uploadDocumentWithMetadata( String documentBody ) throws SecurityConfigurationException,
            IrisException, BadRequestException {
        // Figure out the number of blocks we're sending
        List<VerifiedString> verified = createVerifiedBlocks( documentBody );

        // Create a new pending document on the server
        DocumentCreationRequest documentRequest = new DocumentCreationRequest( verified.size() );
        DocumentId documentId = documentApi.createPendingDocument( documentRequest ).getData();

        // Update this pending document with the necessary blocks to complete the upload
        // Also make sure metadata is uploaded
        return updateDocumentWithMetadata( documentId, documentBody );
    }

    @Override
    public String uploadDocumentWithoutMetadata( String documentBody ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        List<VerifiedString> verified = createVerifiedBlocks( documentBody );
        DocumentCreationRequest documentRequest = new DocumentCreationRequest( verified.size() );
        String documentId = documentApi.createPendingDocument( documentRequest ).getData().getDocumentId();
        return updateDocumentWithoutMetadata( documentId, documentBody, verified );
    }

    @Override
    public String updateDocumentWithMetadata( String documentId, String documentBody )
            throws ResourceNotFoundException, BadRequestException, SecurityConfigurationException, IrisException {
        return updateDocumentWithMetadata( new DocumentId( documentId ), documentBody );
    }

    @Override
    public String updateDocumentWithoutMetadata( String documentId, String documentBody ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        List<VerifiedString> verified = createVerifiedBlocks( documentBody );
        return updateDocumentWithoutMetadata( documentId, documentBody, verified );
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
                    preview += block.getBlock().decrypt( kodex ).getData();
                } catch ( JsonParseException e1 ) {
                    throw new IrisException( e1 );
                } catch ( JsonMappingException e1 ) {
                    throw new IrisException( e1 );
                } catch ( IOException e1 ) {
                    throw new IrisException( e1 );
                } catch ( ClassNotFoundException e1 ) {
                    throw new IrisException( e1 );
                }
            }
            plain.put( e.getKey(), preview );
        }
        return plain;
    }

    /**
     * Utility method to chunk up a document into AES-encryptable blocks and provide some metadata
     * 
     * @param documentBody
     * @return
     * @throws SecurityConfigurationException
     * @throws IrisException
     */
    private List<VerifiedString> createVerifiedBlocks( String documentBody ) throws SecurityConfigurationException,
            IrisException {
        List<VerifiedString> verified = null;
        try {
            verified = AesEncryptableUtils.chunkStringWithVerification( documentBody, kodex );
        } catch ( IOException e ) {
            throw new IrisException( e );
        } catch ( ClassNotFoundException e ) {
            throw new IrisException( e );
        }
        return verified;
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
    private String updateDocumentWithMetadata( DocumentId documentId, String documentBody ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        // upload the document blocks
        updateDocumentWithoutMetadata( documentId.getDocumentId(), documentBody );

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
     * All the other update/uploadDocument functions are syntactic sugar for this method, which actually does all the
     * work to update a document
     * 
     * This chunks up the blocks and uploads them in parallel
     * 
     * @param documentId
     * @param documentBody
     * @param verifiedStringBlocks
     * @return
     * @throws SecurityConfigurationException
     * @throws IrisException
     */
    private String updateDocumentWithoutMetadata(
            final String stringDocumentId,
            String documentBody,
            List<VerifiedString> verifiedStringBlocks ) throws SecurityConfigurationException, IrisException {
        DocumentId documentId = new DocumentId( stringDocumentId );
        Document doc = generateDocument( documentId, documentBody, verifiedStringBlocks );

        submitBlocksToServer( documentId, doc.getBlocks() );

        return stringDocumentId;
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
    private Document generateDocument(
            DocumentId documentId,
            String documentBody,
            List<VerifiedString> verifiedStringBlocks ) throws IrisException, SecurityConfigurationException {
        try {
            return AesEncryptableUtils.createEncryptedDocument(
                    documentId.getDocumentId(),
                    documentBody,
                    VerifiedString.getEncryptables( verifiedStringBlocks ) );
        } catch ( ClassNotFoundException e ) {
            throw new IrisException( e );
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
        ExecutorService exec = Executors.newFixedThreadPool( PARALLEL_NETWORK_THREADS );
        List<Future<Void>> jobs = Lists.newArrayList();

        for ( final DocumentBlock block : blocks ) {
            jobs.add( exec.submit( new Callable<Void>() {

                @Override
                public Void call() throws Exception {
                    // push the block to the server
                    documentApi.updateDocument( documentId.getDocumentId(), block );
                    return null;
                }
            } ) );
        }

        for ( Future<Void> f : jobs ) {
            try {
                log.info( "Document Block Upload completed: " + f.get() );
            } catch ( InterruptedException e ) {
                throw new IrisException( e );
            } catch ( ExecutionException e ) {
                throw new IrisException( e );
            }
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
