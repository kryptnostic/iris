package com.kryptnostic.api.v1.storage;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.put;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import com.google.common.hash.Hashing;
import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.storage.v1.http.ObjectStorageApi;
import com.kryptnostic.storage.v1.http.SearchFunctionStorageApi;
import com.kryptnostic.storage.v1.models.EncryptableBlock;
import com.kryptnostic.storage.v1.models.KryptnosticObject;
import com.kryptnostic.storage.v1.models.ObjectMetadata;
import com.kryptnostic.storage.v1.models.StorageRequestBuilder;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.storage.v1.models.request.PendingObjectRequest;
import com.kryptnostic.utils.SecurityConfigurationTestUtils;

@SuppressWarnings( "javadoc" )
public class DefaultStorageClientTests extends SecurityConfigurationTestUtils {

    private StorageClient            storageService;
    private UUID                     userKey;

    @Rule
    public WireMockRule              wireMockRule = new WireMockRule( 9990 );
    private SimplePolynomialFunction globalHasher;

    @Before
    public void setup() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException, SealedKodexException, IOException, SignatureException, Exception {
        userKey = UUID.randomUUID();

        generateGlobalHasherStub();
        generateQueryHasherPairStub();

        String privateKey = serialize( crypto.encrypt( mapper.writeValueAsBytes( pair.getPrivate().getEncoded() ) ) );
        stubFor( get( urlEqualTo( "/directory/private" ) ).willReturn( jsonResponse( privateKey ) ) );
        stubFor( put( urlEqualTo( "/directory/private" ) ).willReturn( aResponse() ) );
        stubFor( get( urlEqualTo( "/directory/public/krypt/sina" ) ).willReturn(
                jsonResponse( serialize( new PublicKeyEnvelope( pair.getPublic().getEncoded() ) ) ) ) );
        stubFor( put( urlEqualTo( "/directory/public" ) ).willReturn( aResponse() ) );
        String kodexStr = serialize( kodex );
        stubFor( get( urlEqualTo( "/directory/kodex" ) ).willReturn( jsonResponse( kodexStr ) ) );
    }

    private ResponseDefinitionBuilder jsonResponse( String s ) {
        return aResponse().withHeader( "Content-Type", "application/json" ).withBody( s );
    }

    @Test
    public void uploadingWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceNotLockedException, IrisException, SecurityConfigurationException, ResourceLockedException,
            NoSuchAlgorithmException, JsonProcessingException, ExecutionException {
        ObjectStorageApi documentApi = Mockito.mock( ObjectStorageApi.class );
        MetadataStorageApi metadataApi = Mockito.mock( MetadataStorageApi.class );
        SharingApi sharingApi = Mockito.mock( SharingApi.class );
        KryptnosticContext context = Mockito.mock( KryptnosticContext.class );

        Mockito.when( sharingApi.removeIncomingShares( Mockito.anyString() ) ).thenReturn(
                new BasicResponse<String>( "done", 200, true ) );

        Mockito.when( context.getConnection() ).thenReturn( Mockito.mock( IrisConnection.class ) );
        Mockito.when( context.getConnection().getCryptoServiceLoader() ).thenReturn( loader );

        storageService = new DefaultStorageClient( context, documentApi, metadataApi, sharingApi );

        Mockito.when( documentApi.createPendingObject( Mockito.<PendingObjectRequest> any() ) ).then(
                new Answer<BasicResponse<String>>() {

                    @Override
                    public BasicResponse<String> answer( InvocationOnMock invocation ) throws Throwable {
                        return new BasicResponse<String>( "document1", HttpStatus.SC_OK, true );
                    }

                } );

        Mockito.when( documentApi.updateObject( Mockito.anyString(), Mockito.any( EncryptableBlock.class ) ) ).then(
                new Answer<BasicResponse<String>>() {

                    @Override
                    public BasicResponse<String> answer( InvocationOnMock invocation ) throws Throwable {
                        return new BasicResponse<String>( "document1", HttpStatus.SC_OK, true );
                    }

                } );

        Mockito.when( metadataApi.uploadMetadata( Mockito.any( MetadataRequest.class ) ) ).then( new Answer<String>() {

            @Override
            public String answer( InvocationOnMock invocation ) throws Throwable {
                Assert.fail( "No metadata should be uploaded" );
                return null;
            }

        } );

        loader.put( "document1", crypto );
        loader.put( "test", crypto );

        storageService.uploadObject( new StorageRequestBuilder().withBody( "test" ).notSearchable().build() );

        storageService.uploadObject( new StorageRequestBuilder().withBody( "test" ).withId( "test" ).notSearchable()
                .build() );
    }

    @Test
    public void documentFragmentTest() throws BadRequestException, ResourceNotFoundException,
            ResourceNotLockedException, IrisException, SecurityConfigurationException, ResourceLockedException,
            NoSuchAlgorithmException, ExecutionException, ClassNotFoundException, IOException {
        ObjectStorageApi documentApi = Mockito.mock( ObjectStorageApi.class );
        MetadataStorageApi metadataApi = Mockito.mock( MetadataStorageApi.class );
        SharingApi sharingApi = Mockito.mock( SharingApi.class );
        KryptnosticContext context = Mockito.mock( KryptnosticContext.class );

        Mockito.when( sharingApi.removeIncomingShares( Mockito.anyString() ) ).thenReturn(
                new BasicResponse<String>( "done", 200, true ) );

        String word = "word";
        String intermediate = " cool cool ";
        String docBody = word + intermediate + intermediate + word;
        String docId = "doc1";
        loader.put( docId, crypto );
        KryptnosticObject doc = new KryptnosticObject( new ObjectMetadata( docId, null ), docBody ).encrypt( loader );
        Mockito.when( documentApi.getObject( Mockito.anyString() ) ).thenReturn( doc );

        Mockito.when( context.getConnection() ).thenReturn( Mockito.mock( IrisConnection.class ) );
        Mockito.when( context.getConnection().getCryptoServiceLoader() ).thenReturn( loader );

        storageService = new DefaultStorageClient( context, documentApi, metadataApi, sharingApi );

        int secondIndex = ( word + intermediate + intermediate ).length() + 1;
        Map<Integer, String> preview = storageService.getObjectPreview( docId, Arrays.asList( 0, secondIndex ), 2 );
        Assert.assertEquals( 2, preview.size() );
        Assert.assertEquals( ( word + intermediate ).trim(), preview.get( 0 ) );
        Assert.assertEquals( ( intermediate + word ).substring( 1 ), preview.get( secondIndex ) );
    }

    // FIXME duped from DefaultKryptnosticClientTests
    private SimplePolynomialFunction generateGlobalHasherStub() throws IrisException, JsonProcessingException {
        globalHasher = SimplePolynomialFunctions.randomFunction( 128, 128 );
        String globalHasherResponse = null;
        try {
            globalHasherResponse = serialize( globalHasher );
        } catch ( JsonGenerationException e ) {
            throw new IrisException( e );
        } catch ( JsonMappingException e ) {
            throw new IrisException( e );
        } catch ( IOException e ) {
            throw new IrisException( e );
        }

        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER ) ).willReturn(
                aResponse().withBody( globalHasherResponse ) ) );

        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER + SearchFunctionStorageApi.CHECKSUM ) ).willReturn(
                aResponse().withBody(
                        wrap( "\""
                                + Hashing.murmur3_128().hashBytes( mapper.writeValueAsBytes( globalHasher ) )
                                        .toString() + "\"" ) ) ) );
        return globalHasher;
    }

    private void generateQueryHasherPairStub() {
        String response = wrap( "true" );

        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER + SearchFunctionStorageApi.HASHER ) ).willReturn(
                aResponse().withBody( response ) ) );
    }

    private String wrap( String serialize ) {
        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    }
}
