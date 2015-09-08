package com.kryptnostic.api.v1.client;

import com.kryptnostic.utils.SecurityConfigurationTestUtils;

@SuppressWarnings( "javadoc" )
public class DefaultKryptnosticClientTests extends SecurityConfigurationTestUtils {

    // TODO: Build real tests

    // private KryptnosticClient client;
    // private KryptnosticServicesFactory factory;
    // private KryptnosticConnection connection;

    // @Rule
    // public WireMockRule wireMockRule = new WireMockRule( 9990 );
    // private UUID userKey;
    // private InMemoryStore store;
    //
    // @Before
    // public void initClient() throws IrisException, InvalidKeyException, NoSuchAlgorithmException,
    // InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
    // InvalidKeySpecException, InvalidParameterSpecException, IOException,
    // ResourceNotFoundException, SignatureException, Exception {
    // if ( store == null ) {
    // store = new InMemoryStore();
    // }
    // store.clear();
    // if ( client == null ) {
    //
    // // set up http stubs for getting global hasher and checking query pair
    //
    // userKey = UUID.randomUUID();
    //
    // CredentialPair p = CredentialFactory.generateCredentialPair( "test" );
    // stubFor( get( urlEqualTo( DirectoryApi.CONTROLLER + DirectoryApi.SALT_KEY + "/" + userKey ) ).willReturn(
    // jsonResponse( mapper.writeValueAsString( p.getEncryptedSalt() ) ) ) );
    //
    // connection = new IrisConnection(
    // "http://localhost:9990",
    // userKey,
    // "test",
    // store,
    // createHttpClient(),
    // pair );
    //
    // generateDocumentStubs();
    // factory = new DefaultKryptnosticServicesFactory(
    // KryptnosticRestAdapter.createWithDefaultClient( connection ) );
    //
    // client = new DefaultKryptnosticClient( factory, connection );
    // }
    // }
    //
    // private void generateDocumentStubs() {
    // try {
    // stubFor( get( urlMatching( DirectoryApi.CONTROLLER + DirectoryApi.OBJECT_KEY + "/.*" ) ).willReturn(
    // aResponse().withBody(
    // serialize( new BasicResponse<byte[]>( connection.getRsaCryptoService().encrypt(
    // new AesCryptoService( Cypher.AES_CTR_128 ) ), 200, true ) ) ) ) );
    // stubFor( post( urlMatching( DirectoryApi.CONTROLLER + DirectoryApi.OBJECT_KEY + "/.*" ) ).willReturn(
    // aResponse().withBody( serialize( new BasicResponse<String>( "blah", 200, true ) ) ) ) );
    // stubFor( put( urlEqualTo( SharingApi.SHARE + SharingApi.KEYS ) ).willReturn( aResponse() ) );
    // stubFor( post( urlEqualTo( MetadataStorageApi.METADATA ) ).willReturn( jsonResponse( wrap( "\"done\"" ) ) ) );
    // } catch (
    // IOException
    // | SecurityConfigurationException
    // | NoSuchAlgorithmException
    // | InvalidAlgorithmParameterException e ) {
    // e.printStackTrace();
    // }
    // }
    //
    // private ResponseDefinitionBuilder jsonResponse( String s ) {
    // return aResponse().withHeader( "Content-Type", "application/json" ).withBody( s );
    // }
    //
    // private String wrap( String serialize ) {
    // return "{\"data\":" + serialize + ",\"status\":200,\"success\":\"true\"}";
    // }
}
