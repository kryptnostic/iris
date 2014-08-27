package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.client.web.DocumentApi;
import com.kryptnostic.api.v1.client.web.MetadataApi;
import com.kryptnostic.api.v1.client.web.SearchApi;
import com.kryptnostic.api.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger logger = LoggerFactory.getLogger(DefaultKryptnosticServicesFactory.class);

    private static final int TOKEN_LENGTH = 256;
    private static final int NONCE_LENGTH = 64;
    private static final int LOCATION_LENGTH = 64;
    private static final int BUCKET_SIZE = 100;

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
        SimplePolynomialFunction indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH,
                NONCE_LENGTH, LOCATION_LENGTH);
        metadataKeyService = new BalancedMetadataKeyService(indexingHashFunction, BUCKET_SIZE, NONCE_LENGTH);
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
