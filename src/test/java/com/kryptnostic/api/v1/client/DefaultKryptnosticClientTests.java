package com.kryptnostic.api.v1.client;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.putRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlMatching;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.request.AesEncryptableBase;
import com.kryptnostic.users.v1.UserKey;

public class DefaultKryptnosticClientTests extends AesEncryptableBase {

    private KryptnosticClient          client;
    private KryptnosticServicesFactory factory;
    private KryptnosticConnection      connection;
    private SimplePolynomialFunction   expectedGlobalHasher;

    @Rule
    public WireMockRule                wireMockRule = new WireMockRule( 9990 );
    private UserKey                    userKey;

    @Before
    public void initClient() throws IrisException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidParameterSpecException, SealedKodexException, IOException,
            ResourceNotFoundException, SignatureException, Exception {
        if ( client == null ) {
            initImplicitEncryption();
            initFheEncryption();

            userKey = new UserKey( "krypt", "sina" );

            connection = new IrisConnection( kodex, crypto, userKey, "test", "http://localhost:9990" );
            factory = new DefaultKryptnosticServicesFactory(
                    KryptnosticRestAdapter.createWithDefaultClient( connection ) );

            // set up http stubs for getting global hasher and checking query pair
            expectedGlobalHasher = generateGlobalHasherStub();
            generateQueryHasherPairStub();

            client = new DefaultKryptnosticClient( factory, connection );
        }
    }

    @Test
    public void getGlobalHasherTest() throws ResourceNotFoundException, IrisException {
        SimplePolynomialFunction actualGlobalHasher = client.getContext().getGlobalHashFunction();
        Assert.assertEquals( expectedGlobalHasher, actualGlobalHasher );

        // verify we only request the global hasher once (getGlobalHashFunction was called twice though, because it's
        // called during client init)
        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.SEARCH_FUNCTION ) ) );
        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.SEARCH_FUNCTION + "/hasher" ) ) );
    }

    @Test
    public void updateDocumentWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceLockedException, SecurityConfigurationException, IrisException, JsonGenerationException,
            JsonMappingException, IOException, URISyntaxException {
        DocumentId docId = DocumentId.fromUserAndId( "DOCUMENT_0", userKey );
        String documentUpdateUrl = DocumentApi.DOCUMENT + "/" + URLEncoder.encode( docId.toString() );

        String docIdResponse = serialize( new BasicResponse<DocumentId>( docId, 200, true ) );

        stubFor( post( urlMatching( documentUpdateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );

        String receivedDocId = client.updateDocumentWithoutMetadata( docId.getDocumentId(), "test" );

        Assert.assertEquals( docId.getDocumentId(), receivedDocId );

        verify( 1, postRequestedFor( urlMatching( documentUpdateUrl ) ) );
    }

    @Test
    public void uploadDocumentWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceLockedException, SecurityConfigurationException, IrisException, JsonGenerationException,
            JsonMappingException, IOException, URISyntaxException {
        DocumentId docId = DocumentId.fromUserAndId( "DOCUMENT_0", userKey );
        String documentCreateUrl = DocumentApi.DOCUMENT;
        String documentUpdateUrl = DocumentApi.DOCUMENT + "/" + URLEncoder.encode( docId.toString() );

        String docIdResponse = serialize( new BasicResponse<DocumentId>( docId, 200, true ) );

        stubFor( put( urlMatching( documentCreateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );
        stubFor( post( urlMatching( documentUpdateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );

        String receivedDocId = client.uploadDocumentWithoutMetadata( "test" );
        Assert.assertEquals( docId.getDocumentId(), receivedDocId );

        verify( 1, putRequestedFor( urlMatching( documentCreateUrl ) ) );
        verify( 1, postRequestedFor( urlMatching( documentUpdateUrl ) ) );
    }

    private ResponseDefinitionBuilder jsonResponse( String s ) {
        return aResponse().withHeader( "Content-Type", "application/json" ).withBody( s );
    }

    private SimplePolynomialFunction generateGlobalHasherStub() throws IrisException {
        SimplePolynomialFunction expectedGlobalHasher = SimplePolynomialFunctions.randomFunction( 128, 128 );
        String globalHasherResponse = null;
        try {
            globalHasherResponse = serialize( expectedGlobalHasher );
        } catch ( JsonGenerationException e ) {
            throw new IrisException( e );
        } catch ( JsonMappingException e ) {
            throw new IrisException( e );
        } catch ( IOException e ) {
            throw new IrisException( e );
        }

        stubFor( get( urlEqualTo( SearchFunctionApi.SEARCH_FUNCTION ) ).willReturn(
                aResponse().withBody( globalHasherResponse ) ) );
        return expectedGlobalHasher;
    }

    private void generateQueryHasherPairStub() {
        String response = wrap( "true" );
        stubFor( get( urlEqualTo( SearchFunctionApi.SEARCH_FUNCTION + "/hasher" ) ).willReturn(
                aResponse().withBody( response ) ) );
    }

    private String wrap( String serialize ) {
        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    }
}
