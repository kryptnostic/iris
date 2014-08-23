package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

@Configuration
public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger logger = LoggerFactory.getLogger(DefaultKryptnosticServicesFactory.class);

    private static final int TOKEN_LENGTH = 256;
    private static final int NONCE_LENGTH = 64;
    private static final int LOCATION_LENGTH = 64;
    private static final int BUCKET_SIZE = 100;

    private final MetadataKeyService metadataKeyService;
    private final IndexingService indexingService;
    private final KryptnosticStorage storageService;
    private final KryptnosticSearch searchService;

    public DefaultKryptnosticServicesFactory(String url) {
        RestAdapter restAdapter = new RestAdapter.Builder().setConverter(new JacksonConverter()).setEndpoint(url)
                .setErrorHandler(new DefaultErrorHandler()).setLogLevel(LogLevel.FULL).setLog(new RestAdapter.Log() {
                    @Override
                    public void log(String msg) {
                        logger.debug(msg);
                    }
                }).build();
        SimplePolynomialFunction indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH,
                NONCE_LENGTH, LOCATION_LENGTH);
        metadataKeyService = new BalancedMetadataKeyService(indexingHashFunction, BUCKET_SIZE, NONCE_LENGTH);
        indexingService = new BaseIndexingService();
        storageService = restAdapter.create(KryptnosticStorage.class);
        searchService = restAdapter.create(KryptnosticSearch.class);
    }

    @Bean(name="storageService")
    @Override
    public KryptnosticStorage createStorageService() {
        return storageService;
    }

    @Bean(name="searchService")
    @Override
    public KryptnosticSearch createSearchService() {
        return searchService;
    }
    
    @Bean(name="metadataKeyService")
    @Override
    public MetadataKeyService createMetadataKeyService() {
        return metadataKeyService;
    }

    @Bean(name="indexingService")
    @Override
    public IndexingService createIndexingService() {
        return indexingService;
    }

}
