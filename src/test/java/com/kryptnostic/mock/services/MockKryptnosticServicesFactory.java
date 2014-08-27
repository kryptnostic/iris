package com.kryptnostic.mock.services;

import com.kryptnostic.api.v1.client.DefaultKryptnosticContext;
import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;

/**
 * Services factory for testing client.
 * 
 * @author Nick Hewitt
 *
 */
public class MockKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final SearchApi searchService = new MockKryptnosticSearch();
    private final MetadataApi metadataService = new MockKryptnosticMetadata();
    private final DocumentApi documentService = new MockKryptnosticDocument();
    private final KryptnosticContext context;
    private final MetadataKeyService metadataKeyService;
    private final IndexingService indexingService;

    {
        context = new DefaultKryptnosticContext();
        metadataKeyService = new BalancedMetadataKeyService(context);
        indexingService = new BaseIndexingService();
    }

    @Override
    public MetadataApi createMetadataApi() {
        return metadataService;
    }

    @Override
    public DocumentApi createDocumentApi() {
        return documentService;
    }

    @Override
    public SearchApi createSearchApi() {
        return searchService;
    }

    @Override
    public MetadataKeyService createMetadataKeyService() {
        return metadataKeyService;
    }

    @Override
    public IndexingService createIndexingService() {
        return indexingService;
    }

}
