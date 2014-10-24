package com.kryptnostic.api.v1.client;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.kryptnostic.BaseSerializationTest;
import com.kryptnostic.api.v1.security.InMemorySecurityService;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.users.v1.UserKey;

public class DefaultKryptnosticClientTests extends BaseSerializationTest {

    private KryptnosticClient client;

    @Rule
    public WireMockRule       wireMockRule = new WireMockRule( 9990 );

    @Before
    public void initClient() throws IrisException {
        final SecurityService securityService = new InMemorySecurityService( new UserKey( "krypt", "sina" ), "test" );
        final KryptnosticServicesFactory factory = new DefaultKryptnosticServicesFactory(
                KryptnosticRestAdapter.createWithDefaultClient( "http://localhost:9990".toString(), securityService ) );
        client = new DefaultKryptnosticClient( factory, securityService );
    }

    @Test
    public void initTest() {
        Assert.assertNotNull( client.getContext() );
    }

    @Test
    public void globalHasherTest() throws InterruptedException, JsonGenerationException, JsonMappingException,
            IOException, ResourceNotFoundException {
        SimplePolynomialFunction expected = SimplePolynomialFunctions.randomFunction( 128, 128 );
        String response = wrap( serialize( expected ) );

        stubFor( get( urlEqualTo( SearchFunctionApi.SEARCH_FUNCTION ) ).willReturn( aResponse().withBody( response ) ) );

        SimplePolynomialFunction actual = client.getContext().getGlobalHashFunction();
        Assert.assertEquals( expected, actual );

        SimplePolynomialFunction roundTwo = client.getContext().getGlobalHashFunction();
        Assert.assertEquals( expected, roundTwo );

        // verify we only request the global hasher once
        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.SEARCH_FUNCTION ) ) );

    }

    private String wrap( String serialize ) {
        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    }
}
