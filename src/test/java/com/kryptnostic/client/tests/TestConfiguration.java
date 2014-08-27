package com.kryptnostic.client.tests;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.kryptnostic.api.v1.client.DefaultKryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.mock.services.MockKryptnosticServicesFactory;

@Configuration
public class TestConfiguration {
    @Bean
    public KryptnosticContext kryptnosticContext() {
        return new DefaultKryptnosticContext(serviceFactory());
    }

    @Bean
    public KryptnosticServicesFactory serviceFactory() {
        return new MockKryptnosticServicesFactory();
    }
}
