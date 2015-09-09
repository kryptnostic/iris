package com.kryptnostic.api.v1.storage;

import com.kryptnostic.utils.SecurityConfigurationTestUtils;

@SuppressWarnings( "javadoc" )
public class DefaultStorageClientTests extends SecurityConfigurationTestUtils {
//TODO: Real tests.
    
//    private StorageClient            storageService;
//
//    @Rule
//    public WireMockRule              wireMockRule = new WireMockRule( 9990 );
//    private SimplePolynomialFunction globalHasher;
//
//    @Before
//    public void setup() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
//            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidParameterSpecException,
//            InvalidAlgorithmParameterException, IOException, SignatureException, Exception {
//
//        generateGlobalHasherStub();
//        generateQueryHasherPairStub();
//
//        String privateKey = serialize( crypto.encrypt( mapper.writeValueAsBytes( pair.getPrivate().getEncoded() ) ) );
//        stubFor( get( urlEqualTo( "/directory/private" ) ).willReturn( jsonResponse( privateKey ) ) );
//        stubFor( put( urlEqualTo( "/directory/private" ) ).willReturn( aResponse() ) );
//        stubFor( get( urlEqualTo( "/directory/public/krypt/sina" ) ).willReturn(
//                jsonResponse( serialize( new PublicKeyEnvelope( pair.getPublic().getEncoded() ) ) ) ) );
//        stubFor( put( urlEqualTo( "/directory/public" ) ).willReturn( aResponse() ) );
//    }
//
//    private ResponseDefinitionBuilder jsonResponse( String s ) {
//        return aResponse().withHeader( "Content-Type", "application/json" ).withBody( s );
//    }
//
//    // FIXME duped from DefaultKryptnosticClientTests
//    private SimplePolynomialFunction generateGlobalHasherStub() throws IrisException, JsonProcessingException {
//        globalHasher = SimplePolynomialFunctions.randomFunction( 128, 128 );
//        String globalHasherResponse = null;
//        try {
//            globalHasherResponse = serialize( globalHasher );
//        } catch ( JsonGenerationException e ) {
//            throw new IrisException( e );
//        } catch ( JsonMappingException e ) {
//            throw new IrisException( e );
//        } catch ( IOException e ) {
//            throw new IrisException( e );
//        }
//
//        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER ) ).willReturn(
//                aResponse().withBody( globalHasherResponse ) ) );
//
//        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER + SearchFunctionStorageApi.CHECKSUM ) )
//                .willReturn(
//                        aResponse().withBody(
//                                wrap( "\""
//                                        + Hashing.murmur3_128().hashBytes( mapper.writeValueAsBytes( globalHasher ) )
//                                                .toString() + "\"" ) ) ) );
//        return globalHasher;
//    }
//
//    private void generateQueryHasherPairStub() {
//        String response = wrap( "true" );
//
//        stubFor( get( urlEqualTo( SearchFunctionStorageApi.CONTROLLER + SearchFunctionStorageApi.HASHER ) ).willReturn(
//                aResponse().withBody( response ) ) );
//    }
//
//    private String wrap( String serialize ) {
//        return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
//    }
}
 