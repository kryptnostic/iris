package com.kryptnostic.mock.services;

import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
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
    private static final int TOKEN_LENGTH = 256;
    private static final int NONCE_LENGTH = 64;
    private static final int LOCATION_LENGTH = 64;
    private static final int BUCKET_SIZE = 100;
    
    private final SearchApi searchService = new MockKryptnosticSearch();
    private final MetadataApi metadataService = new MockKryptnosticMetadata();
    private final DocumentApi documentService = new MockKryptnosticDocument();
    private final MetadataKeyService metadataKeyService;
    private final IndexingService indexingService;
    
    {
        SimplePolynomialFunction indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH,
                NONCE_LENGTH, LOCATION_LENGTH);
        metadataKeyService = new BalancedMetadataKeyService(indexingHashFunction, BUCKET_SIZE, NONCE_LENGTH);
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
