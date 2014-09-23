package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.security.InMemorySecurityService;
import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.client.NonceApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger logger = LoggerFactory.getLogger(DefaultKryptnosticServicesFactory.class);

    private MetadataKeyService metadataKeyService;
    private final IndexingService indexingService;
    private final MetadataApi metadataService;
    private final DocumentApi documentService;
    private final SearchApi searchService;
    private final NonceApi nonceService;
    private final SearchFunctionApi searchFunctionService;
    private final SecurityService securityService;

    public DefaultKryptnosticServicesFactory(String url) {
        // security
        // TODO: replace with a persistent service to store keys for reuse
        securityService = new InMemorySecurityService();

        // connection
        RestAdapter restAdapter = new RestAdapter.Builder()
                .setConverter(new JacksonConverter(securityService.getSecurityConfigurationMapping())).setEndpoint(url)
                .setErrorHandler(new DefaultErrorHandler()).setLogLevel(LogLevel.FULL).setLog(new RestAdapter.Log() {
                    @Override
                    public void log(String msg) {
                        logger.debug(msg);
                    }
                }).build();

        documentService = restAdapter.create(DocumentApi.class);
        metadataService = restAdapter.create(MetadataApi.class);
        searchService = restAdapter.create(SearchApi.class);
        nonceService = restAdapter.create(NonceApi.class);
        searchFunctionService = restAdapter.create(SearchFunctionApi.class);

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
    public MetadataKeyService createMetadataKeyService(KryptnosticContext context) {
        if (metadataKeyService == null) {
            this.metadataKeyService = new BalancedMetadataKeyService(context);
        }
        return metadataKeyService;
    }

    @Override
    public IndexingService createIndexingService() {
        return indexingService;
    }

    @Override
    public SearchFunctionApi createSearchFunctionService() {
        return searchFunctionService;
    }

    @Override
    public NonceApi createNonceService() {
        return nonceService;
    }

    @Override
    public SecurityService createSecurityService() {
        return securityService;
    }
}
