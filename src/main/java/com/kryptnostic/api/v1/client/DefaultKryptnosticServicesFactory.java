package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger logger = LoggerFactory.getLogger(DefaultKryptnosticServicesFactory.class);

    private final MetadataKeyService metadataKeyService;
    private final IndexingService indexingService;
    private final MetadataApi metadataApi;
    private final DocumentApi documentApi;
    private final SearchApi searchService;

    public DefaultKryptnosticServicesFactory(String url) {
        // connection
        RestAdapter restAdapter = new RestAdapter.Builder().setConverter(new JacksonConverter()).setEndpoint(url)
                .setErrorHandler(new DefaultErrorHandler()).setLogLevel(LogLevel.FULL).setLog(new RestAdapter.Log() {
                    @Override
                    public void log(String msg) {
                        logger.debug(msg);
                    }
                }).build();

        documentApi = restAdapter.create(DocumentApi.class);
        metadataApi = restAdapter.create(MetadataApi.class);
        searchService = restAdapter.create(SearchApi.class);

        // context
        KryptnosticContext context = new DefaultKryptnosticContext();

        metadataKeyService = new BalancedMetadataKeyService(context);
        indexingService = new BaseIndexingService();
    }

    public MetadataApi createMetadataApi() {
        return metadataApi;
    }

    public DocumentApi createDocumentApi() {
        return documentApi;
    }

    public SearchApi createSearchApi() {
        return searchService;
    }

    public MetadataKeyService createMetadataKeyService() {
        return metadataKeyService;
    }

    public IndexingService createIndexingService() {
        return indexingService;
    }

}
