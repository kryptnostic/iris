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
import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.users.v1.UserKey;

public class DefaultKryptnosticClientTests extends BaseSerializationTest {

    private KryptnosticClient          client;
    private KryptnosticServicesFactory factory;
    private KryptnosticConnection            securityService;

    @Rule
    public WireMockRule                wireMockRule = new WireMockRule( 9990 );

    @Before
    public void initClient() {
        securityService = new IrisConnection( new UserKey( "krypt", "sina" ), "test" );
        factory = new DefaultKryptnosticServicesFactory( KryptnosticRestAdapter.createWithDefaultClient(
                "http://localhost:9990",
                securityService ) );
    }

    @Test
    public void initTest() throws InterruptedException, JsonGenerationException, JsonMappingException, IOException,
            ResourceNotFoundException, IrisException {
        // set up http stubs for getting global hasher and checking query pair
        SimplePolynomialFunction expectedGlobalHasher = generateGlobalHasherStub();
        generateQueryHasherPairStub();

        KryptnosticClient client = new DefaultKryptnosticClient( factory, securityService );

        SimplePolynomialFunction actualGlobalHasher = client.getContext().getGlobalHashFunction();
        Assert.assertEquals( expectedGlobalHasher, actualGlobalHasher );

        // verify we only request the global hasher once (getGlobalHashFunction was called twice though, because it's
        // called during client init)
        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.SEARCH_FUNCTION ) ) );

        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.SEARCH_FUNCTION + "/hasher" ) ) );

    }

    private SimplePolynomialFunction generateGlobalHasherStub() throws JsonGenerationException, JsonMappingException,
            IOException {
        SimplePolynomialFunction expectedGlobalHasher = SimplePolynomialFunctions.randomFunction( 128, 128 );
        String globalHasherResponse = serialize( expectedGlobalHasher );

        stubFor( get( urlEqualTo( SearchFunctionApi.SEARCH_FUNCTION ) ).willReturn(
                aResponse().withBody( globalHasherResponse ) ) );
        return expectedGlobalHasher;
    }

    private void generateQueryHasherPairStub() throws JsonGenerationException, JsonMappingException, IOException {
        String response = wrap( "true" );
        stubFor( get( urlEqualTo( SearchFunctionApi.SEARCH_FUNCTION + "/hasher" ) ).willReturn(
                aResponse().withBody( response ) ) );
    }

    private String wrap( String serialize ) {
        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    }
}
