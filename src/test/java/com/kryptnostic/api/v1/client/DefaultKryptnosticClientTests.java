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
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.hash.Hashing;
import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.api.v1.storage.DefaultStorageClient.StorageRequestBuilder;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.directory.v1.models.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.http.DocumentApi;
import com.kryptnostic.storage.v1.http.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;
import com.kryptnostic.utils.SecurityConfigurationTestUtils;

@SuppressWarnings( "javadoc" )
public class DefaultKryptnosticClientTests extends SecurityConfigurationTestUtils {

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
            initializeCryptoService();

            // set up http stubs for getting global hasher and checking query pair
            expectedGlobalHasher = generateGlobalHasherStub();
            generateKodex( expectedGlobalHasher );
            generateQueryHasherPairStub();
            // generateDirectoryStubs();
            // generateKodexStubs();

            userKey = new UserKey( "krypt", "sina" );
            connection = new IrisConnection(
                    "http://localhost:9990",
                    userKey,
                    "test",
                    new InMemoryStore(),
                    createHttpClient(),
                    kodex,
                    pair );

            generateDocumentStubs();
            factory = new DefaultKryptnosticServicesFactory(
                    KryptnosticRestAdapter.createWithDefaultClient( connection ) );

            client = new DefaultKryptnosticClient( factory, connection );
        }
    }

    private void generateDocumentStubs() {
        try {
            stubFor( get( urlEqualTo( "/directory/document/DOCUMENT_0" ) ).willReturn(
                    aResponse().withBody(
                            serialize( new BasicResponse<byte[]>( connection.getRsaCryptoService().encrypt(
                                    new AesCryptoService( Cypher.AES_CTR_128 ) ), 200, true ) ) ) ) );
        } catch (
                IOException
                | SecurityConfigurationException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e ) {
            e.printStackTrace();
        }
    }

    private void generateDirectoryStubs() {
        try {
            String privateKey = serialize( crypto.encrypt( mapper.writeValueAsBytes( pair.getPrivate().getEncoded() ) ) );
            stubFor( get( urlEqualTo( "/directory/private" ) ).willReturn( jsonResponse( privateKey ) ) );
            stubFor( put( urlEqualTo( "/directory/private" ) ).willReturn( aResponse() ) );
            stubFor( get( urlEqualTo( "/directory/public/krypt/sina" ) ).willReturn(
                    jsonResponse( serialize( new PublicKeyEnvelope( pair.getPublic().getEncoded() ) ) ) ) );
            stubFor( put( urlEqualTo( "/directory/public" ) ).willReturn( aResponse() ) );
            //
            // String kodexStr = serialize( kodex );
            // stubFor( get( urlEqualTo( "/directory/kodex" ) ).willReturn( jsonResponse( kodexStr ) ) );
        } catch ( IOException | SecurityConfigurationException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private void generateKodexStubs() throws JsonGenerationException, JsonMappingException, IOException {
        stubFor( put( urlMatching( DirectoryApi.CONTROLLER + DirectoryApi.KODEX ) ).willReturn(
                jsonResponse( serialize( new BasicResponse<String>( "", 200, true ) ) ) ) );
    }

    @Test
    @Ignore
    public void getGlobalHasherTest() throws ResourceNotFoundException, IrisException {
        SimplePolynomialFunction actualGlobalHasher = client.getContext().getGlobalHashFunction();
        Assert.assertEquals( expectedGlobalHasher, actualGlobalHasher );

        // verify we only request the global hasher once (getGlobalHashFunction was called twice though, because it's
        // called during client init)
        verify( 1, getRequestedFor( urlMatching( SearchFunctionApi.CONTROLLER ) ) );

    }

    @Test
    @Ignore
    // This test works, but cannot be run with upload test
    public void updateDocumentWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceLockedException, SecurityConfigurationException, IrisException, JsonGenerationException,
            JsonMappingException, IOException, URISyntaxException {
        String docId = "DOCUMENT_1";
        String documentUpdateUrl = DocumentApi.DOCUMENT + "/" + docId;

        String docIdResponse = serialize( new BasicResponse<String>( docId, 200, true ) );

        stubFor( post( urlMatching( documentUpdateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );

        String receivedDocId = client.getStorageClient().uploadDocument(
                new StorageRequestBuilder().withBody( "test" ).withId( docId ).build() );

        Assert.assertEquals( docId, receivedDocId );

        verify( 1, postRequestedFor( urlMatching( documentUpdateUrl ) ) );
    }

    @Test
    public void uploadDocumentWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceLockedException, SecurityConfigurationException, IrisException, JsonGenerationException,
            JsonMappingException, IOException, URISyntaxException {
        String docId = "DOCUMENT_0";
        String documentCreateUrl = DocumentApi.DOCUMENT;
        String documentUpdateUrl = DocumentApi.DOCUMENT + "/" + docId;

        String docIdResponse = serialize( new BasicResponse<String>( docId, 200, true ) );

        stubFor( put( urlMatching( documentCreateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );
        stubFor( post( urlMatching( documentUpdateUrl ) ).willReturn( jsonResponse( docIdResponse ) ) );

        String receivedDocId = client.getStorageClient().uploadDocument(
                new StorageRequestBuilder().withBody( "test" ).notSearchable().build() );
        Assert.assertEquals( docId, receivedDocId );

        verify( 1, putRequestedFor( urlMatching( documentCreateUrl ) ) );
        verify( 1, postRequestedFor( urlMatching( documentUpdateUrl ) ) );
    }

    private ResponseDefinitionBuilder jsonResponse( String s ) {
        return aResponse().withHeader( "Content-Type", "application/json" ).withBody( s );
    }

    private SimplePolynomialFunction generateGlobalHasherStub() throws IrisException, JsonProcessingException {
        SimplePolynomialFunction expectedGlobalHasher = SimplePolynomialFunctions.denseRandomMultivariateQuadratic(
                128,
                64 );
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

        stubFor( get( urlEqualTo( SearchFunctionApi.CONTROLLER ) ).willReturn(
                aResponse().withBody( globalHasherResponse ) ) );

        stubFor( get( urlEqualTo( SearchFunctionApi.CONTROLLER + SearchFunctionApi.CHECKSUM ) ).willReturn(
                aResponse().withBody(
                        wrap( "\""
                                + Hashing.murmur3_128().hashBytes( mapper.writeValueAsBytes( expectedGlobalHasher ) )
                                        .toString() + "\"" ) ) ) );
        return expectedGlobalHasher;
    }

    private void generateQueryHasherPairStub() {
        String response = wrap( "true" );

        stubFor( get( urlEqualTo( SearchFunctionApi.CONTROLLER + SearchFunctionApi.HASHER ) ).willReturn(
                aResponse().withBody( response ) ) );

        try {
            String qhp = kodex.getKeyWithJackson( QueryHasherPairRequest.class.getCanonicalName(), String.class );
            stubFor( get(
                    urlEqualTo( SearchFunctionApi.CONTROLLER + SearchFunctionApi.HASHER + SearchFunctionApi.CHECKSUM ) )
                    .willReturn( jsonResponse( wrap( "\"" + qhp + "\"" ) ) ) );
        } catch ( KodexException | SecurityConfigurationException | SealedKodexException e ) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        stubFor( post( urlEqualTo( SearchFunctionApi.CONTROLLER + SearchFunctionApi.HASHER ) ).willReturn( aResponse() ) );
    }

    private String wrap( String serialize ) {
        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    }
}
