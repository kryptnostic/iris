package com.kryptnostic.client.tests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.kryptnostic.api.v1.client.DefaultKryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.mock.services.MockKryptnosticServicesFactory;

@Configuration
public class TestConfiguration {
    @Bean
    public KryptnosticClient kryptnosticClient() {
        return new DefaultKryptnosticClient(serviceFactory());
    }

    @Bean
    public KryptnosticServicesFactory serviceFactory() {
        return new MockKryptnosticServicesFactory();
    }
}
