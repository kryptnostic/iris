package com.kryptnostic.client.tests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.kryptnostic.api.v1.client.DefaultKryptnosticContext;
import com.kryptnostic.api.v1.client.KryptnosticContext;
import com.kryptnostic.api.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.api.v1.client.SearchAPI;
import com.kryptnostic.api.v1.client.StorageAPI;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.mock.services.MockKryptnosticServicesFactory;

@Configuration
public class TestConfiguration {
    @Bean
    public KryptnosticContext kryptnosticContext() {
        return new DefaultKryptnosticContext(storageService(), searchService(), metadataKeyService(), indexingService());
    }

    @Bean
    public KryptnosticServicesFactory serviceFactory() {
        return new MockKryptnosticServicesFactory();
    }

    @Bean
    public StorageAPI storageService() {
        return serviceFactory().createStorageService();
    }

    @Bean
    public SearchAPI searchService() {
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
