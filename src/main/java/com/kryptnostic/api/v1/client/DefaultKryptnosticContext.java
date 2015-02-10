package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;

import org.apache.commons.codec.binary.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cyphers;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.JacksonKodexMarshaller;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.linear.EnhancedBitMatrix;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.sharing.v1.models.DocumentId;
import com.kryptnostic.storage.v1.http.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;

/**
 * 
 * The default kryptnostic context is instantiated from an
 * 
 * @author Sina Iman &lt;sina@kryptnostic.com&gt;
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultKryptnosticContext implements KryptnosticContext {
    private static DeflatingJacksonMarshaller marshaller      = new DeflatingJacksonMarshaller();
    private final SharingApi                  sharingClient;
    private final DirectoryApi                directoryClient;
    private final SearchFunctionApi           searchFunctionClient;
    private SimplePolynomialFunction          globalHashFunction;
    private final KryptnosticConnection       connection;

    public static final String                CHECKSUM_KEY    = "global.hash.checksum";
    public static final String                FUNCTION_KEY    = "global.hash.function";

    private static final Logger               logger          = LoggerFactory
                                                                      .getLogger( DefaultKryptnosticContext.class );

    private static final int                  TOKEN_LENGTH    = 256;
    private static final int                  LOCATION_LENGTH = 64;
    private static final int                  NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext(
            SearchFunctionApi searchFunctionClient,
            SharingApi sharingClient,
            DirectoryApi directoryClient,
            KryptnosticConnection connection ) throws IrisException {
        this.searchFunctionClient = searchFunctionClient;
        this.sharingClient = sharingClient;
        this.directoryClient = directoryClient;
        this.connection = connection;
        this.globalHashFunction = null;
    }

    @Override
    public KryptnosticConnection getConnection() {
        return this.connection;
    }

    @Override
    public BitVector generateSearchNonce() {
        return BitVectors.randomVector( NONCE_LENGTH );
    }

    @Override
    public SimplePolynomialFunction getGlobalHashFunction() throws ResourceNotFoundException {
        if ( globalHashFunction == null ) {
            byte[] gbh = null;
            String checksum = null;
            try {
                checksum = StringUtils.newStringUtf8( connection.getDataStore().get( CHECKSUM_KEY ) );
                gbh = connection.getDataStore().get( FUNCTION_KEY );
            } catch ( IOException e ) {

            }
            // If function isn't set retrieve it and persist it.
            if ( gbh == null ) {
                globalHashFunction = searchFunctionClient.getFunction();
                try {
                    gbh = new JacksonKodexMarshaller<SimplePolynomialFunction>( SimplePolynomialFunction.class )
                            .toBytes( globalHashFunction );
                } catch ( IOException e1 ) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
                checksum = searchFunctionClient.getGlobalHasherChecksum().getData();// Hashing.murmur3_128().hashBytes(
                                                                                    // gbh ).toString();
                try {
                    connection.getDataStore().put( CHECKSUM_KEY, StringUtils.getBytesUtf8( checksum ) );
                    connection.getDataStore().put( FUNCTION_KEY, gbh );
                } catch ( IOException e ) {
                    logger.error( "Unable to save global hash function. Will try again upon restart." );
                    return null;
                }
            } else {
                // Verify integrity of global hash function
                Preconditions.checkState( searchFunctionClient.getGlobalHasherChecksum().getData().equals( checksum ) );
                try {
                    globalHashFunction = new JacksonKodexMarshaller<SimplePolynomialFunction>(
                            SimplePolynomialFunction.class ).fromBytes( gbh );
                } catch ( IOException e ) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        }

        return globalHashFunction;
    }

    @Override
    public EncryptedSearchSharingKey generateSharingKey() {
        EnhancedBitMatrix documentKey = connection.getEncryptedSearchPrivateKey().newDocumentKey();
        EncryptedSearchSharingKey sharingKey = new EncryptedSearchSharingKey( documentKey );

        return sharingKey;
    }

    @Override
    public EncryptedSearchBridgeKey fromSharingKey( EncryptedSearchSharingKey sharingKey ) throws IrisException {
        try {
            return new EncryptedSearchBridgeKey( connection.getEncryptedSearchPrivateKey(), sharingKey );
        } catch ( SingularMatrixException e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public void submitBridgeKeyWithSearchNonce( DocumentId documentId, EncryptedSearchSharingKey sharingKey )
            throws IrisException {

        try {
            connection.getDataStore().put(
                    documentId.getDocumentId(),
                    EncryptedSearchSharingKey.class.getCanonicalName(),
                    marshaller.toBytes( sharingKey ) );
        } catch ( IOException e1 ) {
            e1.printStackTrace();
        }

        EncryptedSearchBridgeKey bridgeKey = fromSharingKey( sharingKey );

        EncryptedSearchDocumentKey docKey = new EncryptedSearchDocumentKey( bridgeKey, documentId );

        sharingClient.registerKeys( ImmutableSet.of( docKey ) );
    }

    @Override
    public BitVector encryptNonce( BitVector nonce ) {
        SimplePolynomialFunction encrypter = connection.getFhePublicKey().getEncrypter();
        return encrypter.apply( nonce, BitVectors.randomVector( nonce.size() ) );
    }

    @Override
    public BitVector generateIndexForToken( String token, EncryptedSearchSharingKey sharingKey )
            throws ResourceNotFoundException {
        BitVector searchHash = connection.getEncryptedSearchPrivateKey().hash( token );
        EnhancedBitMatrix expectedMatrix = EnhancedBitMatrix.squareMatrixfromBitVector( getGlobalHashFunction().apply(
                searchHash ) );
        BitVector indexForTerm = BitVectors.fromSquareMatrix( expectedMatrix.multiply( sharingKey.getMiddle() )
                .multiply( expectedMatrix ) );
        return indexForTerm;
    }

    @Override
    public BitVector prepareSearchToken( String token ) {
        return connection.getEncryptedSearchPrivateKey().prepareSearchToken( connection.getFhePublicKey(), token );
    }

    @Override
    public byte[] rsaDecrypt( byte[] ciphertext ) throws SecurityConfigurationException {
        return Cyphers.decrypt( RsaKeyLoader.CIPHER, connection.getRsaPrivateKey(), ciphertext );
    }

    @Override
    public byte[] rsaEncrypt( byte[] plaintext ) throws SecurityConfigurationException {
        return Cyphers.encrypt( RsaKeyLoader.CIPHER, connection.getRsaPublicKey(), plaintext );
    }

    @Override
    public Map<UserKey, RsaCompressingEncryptionService> getEncryptionServiceForUsers( Set<UserKey> users ) {
        return Maps.asMap( users, new Function<UserKey, RsaCompressingEncryptionService>() {

            @Override
            public RsaCompressingEncryptionService apply( UserKey input ) {
                try {
                    return new RsaCompressingEncryptionService( RsaKeyLoader.CIPHER, directoryClient.getPublicKey(
                            input.getRealm(),
                            input.getName() ).asRsaPublicKey() );
                } catch ( InvalidKeySpecException | NoSuchAlgorithmException | SecurityConfigurationException e ) {
                    return null;
                }
            }
        } );
    }

    @Override
    public RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException {
        return connection.getRsaCryptoService();
    }
}
