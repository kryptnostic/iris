package com.kryptnostic.client.tests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.kryptnostic.api.v1.client.DefaultKryptnosticConnection;
import com.kryptnostic.api.v1.client.KryptnosticConnection;
import com.kryptnostic.api.v1.client.KryptnosticSearch;
import com.kryptnostic.api.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.api.v1.client.KryptnosticStorage;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.mock.services.MockKryptnosticServicesFactory;

@Configuration
public class TestConfiguration {
    @Bean
    public KryptnosticConnection kryptnosticConnection() {
        return new DefaultKryptnosticConnection(storageService(), searchService(), metadataKeyService(),
                indexingService());
    }

    @Bean
    public KryptnosticServicesFactory serviceFactory() {
        return new MockKryptnosticServicesFactory();
    }

    @Bean
    public KryptnosticStorage storageService() {
        return serviceFactory().createStorageService();
    }

    @Bean
    public KryptnosticSearch searchService() {
        return serviceFactory().createSearchService();
    }

    @Bean
    public MetadataKeyService metadataKeyService() {
        return serviceFactory().createMetadataKeyService();
    }

    @Bean
    public IndexingService indexingService() {
        return serviceFactory().createIndexingService();
    }
}
