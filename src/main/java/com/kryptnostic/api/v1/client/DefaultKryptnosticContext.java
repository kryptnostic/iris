package com.kryptnostic.api.v1.client;

import java.util.Set;

import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.search.DefaultSearchService;
import com.kryptnostic.api.v1.search.SearchService;
import com.kryptnostic.api.v1.storage.DefaultStorageService;
import com.kryptnostic.api.v1.storage.StorageService;

// TODO: exception handling
public class DefaultKryptnosticContext implements KryptnosticContext {
    private final SearchService searchService;
    private final StorageService storageService;

    public DefaultKryptnosticContext(StorageAPI storageService, SearchAPI searchService, MetadataKeyService keyService,
            IndexingService indexingService) {
        this.storageService = new DefaultStorageService(storageService, keyService, indexingService);
        this.searchService = new DefaultSearchService(searchService, indexingService);
    }

    @Override
    public Set<Metadatum> search(String query) {
        return searchService.search(query);
    }

    @Override
    public String uploadDocument(String document) throws BadRequestException {
        return storageService.uploadDocument(document);
    }

    @Override
    public String updateDocument(String id, String document) throws ResourceNotFoundException {
        return storageService.updateDocument(id, document);
    }

    @Override
    public String getDocument(String id) throws ResourceNotFoundException {
        return storageService.getDocument(id);
    }
}
