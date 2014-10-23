package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.kryptnostic.api.v1.search.DefaultSearchService;
import com.kryptnostic.api.v1.storage.DefaultStorageService;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.search.v1.SearchService;
import com.kryptnostic.search.v1.models.SearchResult;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.storage.v1.StorageService;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

// TODO: exception handling
public class DefaultKryptnosticClient implements KryptnosticClient {
    private final SearchService      searchService;
    private final StorageService     storageService;
    private final KryptnosticContext context;

    public DefaultKryptnosticClient( KryptnosticServicesFactory factory ) {
        this.context = new DefaultKryptnosticContext(
                factory.createSearchFunctionService(),
                factory.createDocumentKeyService(),
                factory.createSecurityService() );

        this.storageService = new DefaultStorageService(
                factory.createDocumentApi(),
                factory.createMetadataApi(),
                factory.createMetadataKeyService( context ),
                factory.createIndexingService(),
                context.getSecurityService().getSecurityConfigurationMapping(),
                context.getSecurityService().getUserKey() );
        this.searchService = new DefaultSearchService( factory.createSearchApi(), factory.createIndexingService() );
    }

    @Override
    public Collection<SearchResult> search( String query ) {
        return searchService.search( query );
    }

    @Override
    public String uploadDocument( String document ) throws BadRequestException, SecurityConfigurationException,
            IOException, ResourceNotFoundException, ClassNotFoundException {
        return storageService.uploadDocument( document );
    }

    @Override
    public String updateDocument( String id, String document ) throws ResourceNotFoundException, BadRequestException,
            SecurityConfigurationException, IOException, ClassNotFoundException {
        return storageService.updateDocument( id, document );
    }

    @Override
    public Document getDocument( DocumentId id ) throws ResourceNotFoundException {
        return storageService.getDocument( id );
    }

    @Override
    public KryptnosticContext getContext() {
        return this.context;
    }

    @Override
    public String uploadMetadata( MetadataRequest metadata ) throws BadRequestException {
        return storageService.uploadMetadata( metadata );
    }

    @Override
    public Collection<DocumentId> getDocumentIds() {
        return storageService.getDocumentIds();
    }

    @Override
    public String uploadDocumentWithoutMetadata( String document ) throws BadRequestException,
            SecurityConfigurationException, IOException, ClassNotFoundException {
        return storageService.uploadDocumentWithoutMetadata( document );
    }

    @Override
    public Map<Integer, String> getDocumentFragments( DocumentId id, List<Integer> offsets, int characterWindow )
            throws ResourceNotFoundException, JsonParseException, JsonMappingException, IOException,
            ClassNotFoundException, SecurityConfigurationException {
        return storageService.getDocumentFragments( id, offsets, characterWindow );
    }

    @Override
    public String updateDocumentWithoutMetadata( String id, String document ) throws BadRequestException,
            SecurityConfigurationException, IOException, ClassNotFoundException {
        return storageService.updateDocumentWithoutMetadata( id, document );
    }
}
