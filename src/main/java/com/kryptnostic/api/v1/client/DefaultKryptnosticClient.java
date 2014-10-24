package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.kryptnostic.api.v1.indexing.PaddedMetadataMapper;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.api.v1.search.DefaultSearchClient;
import com.kryptnostic.api.v1.storage.DefaultStorageClient;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.search.v1.models.SearchResult;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class DefaultKryptnosticClient implements KryptnosticClient {
    private final SearchClient       searchClient;
    private final StorageClient      storageClient;
    private final KryptnosticContext context;

    public DefaultKryptnosticClient( KryptnosticServicesFactory factory, SecurityService securityService ) throws IrisException {
        this.context = new DefaultKryptnosticContext(
                factory.createSearchFunctionApi(),
                securityService );

        Indexer indexer = new SimpleIndexer( securityService.getUserKey() );

        this.storageClient = new DefaultStorageClient(
                factory.createDocumentApi(),
                factory.createMetadataApi(),
                new PaddedMetadataMapper( context ),
                indexer,
                context.getSecurityService() );
        this.searchClient = new DefaultSearchClient( factory.createSearchApi(), indexer );
    }

    @Override
    public Collection<SearchResult> search( String query ) {
        return searchClient.search( query );
    }

    @Override
    public String uploadDocumentWithMetadata( String document ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        return storageClient.uploadDocumentWithMetadata( document );
    }

    @Override
    public String uploadDocumentWithoutMetadata( String document ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        return storageClient.uploadDocumentWithoutMetadata( document );
    }

    @Override
    public String updateDocumentWithMetadata( String id, String document ) throws ResourceNotFoundException,
            BadRequestException, SecurityConfigurationException, ResourceLockedException, IrisException {
        return storageClient.updateDocumentWithMetadata( id, document );
    }

    @Override
    public String updateDocumentWithoutMetadata( String id, String document ) throws BadRequestException,
            SecurityConfigurationException, ResourceNotFoundException, ResourceLockedException, IrisException {
        return storageClient.updateDocumentWithoutMetadata( id, document );
    }

    @Override
    public Document getDocument( DocumentId id ) throws ResourceNotFoundException {
        return storageClient.getDocument( id );
    }

    @Override
    public KryptnosticContext getContext() {
        return this.context;
    }

    @Override
    public String uploadMetadata( MetadataRequest metadata ) throws BadRequestException {
        return storageClient.uploadMetadata( metadata );
    }

    @Override
    public Collection<DocumentId> getDocumentIds() {
        return storageClient.getDocumentIds();
    }

    @Override
    public Map<Integer, String> getDocumentFragments( DocumentId id, List<Integer> offsets, int characterWindow )
            throws ResourceNotFoundException, SecurityConfigurationException, IrisException {
        return storageClient.getDocumentFragments( id, offsets, characterWindow );
    }

}
