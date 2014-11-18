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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.models.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cyphers;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.crypto.keys.JacksonKodexMarshaller;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
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
    private final ObjectMapper                mapper          = KodexObjectMapperFactory.getObjectMapper();
    private static DeflatingJacksonMarshaller marshaller      = new DeflatingJacksonMarshaller();
    private final SharingApi                  sharingClient;
    private final DirectoryApi                directoryClient;
    private final SearchFunctionApi           searchFunctionClient;
    private final PrivateKey                  fhePrivateKey;
    private final PublicKey                   fhePublicKey;
    private final EncryptedSearchPrivateKey   encryptedSearchPrivateKey;
    private final KryptnosticConnection       securityService;
    private final DataStore                   dataStore;
    private SimplePolynomialFunction          globalHashFunction;

    public static final String                CHECKSUM_KEY    = "global-hash-checksum";
    public static final String                FUNCTION_KEY    = "global-hash-function";

    private static final Logger               logger          = LoggerFactory
                                                                      .getLogger( DefaultKryptnosticContext.class );

    private static final int                  TOKEN_LENGTH    = 256;
    private static final int                  LOCATION_LENGTH = 64;
    private static final int                  NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext(
            SearchFunctionApi searchFunctionClient,
            SharingApi sharingClient,
            DirectoryApi directoryClient,
            KryptnosticConnection securityService ) throws IrisException {
        this.searchFunctionClient = searchFunctionClient;
        this.sharingClient = sharingClient;
        this.directoryClient = directoryClient;
        this.securityService = securityService;
        this.fhePublicKey = securityService.getFhePublicKey();
        this.fhePrivateKey = securityService.getFhePrivateKey();
        this.encryptedSearchPrivateKey = securityService.getEncryptedSearchPrivateKey();
        this.dataStore = securityService.getDataStore();
    }

    @Override
    public KryptnosticConnection getConnection() {
        return this.securityService;
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
                checksum = StringUtils.newStringUtf8( dataStore.get( CHECKSUM_KEY.getBytes() ) );
                gbh = dataStore.get( FUNCTION_KEY.getBytes() );
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
                    dataStore.put( CHECKSUM_KEY.getBytes(), StringUtils.getBytesUtf8( checksum ) );
                    dataStore.put( FUNCTION_KEY.getBytes(), gbh );
                } catch ( IOException e ) {
                    logger.error( "Unable to save global hash function. Will try again upon restart." );
                    return null;
                }
            } else {
                // Verify integrity of glabal hash function
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

        EnhancedBitMatrix documentKey = encryptedSearchPrivateKey.newDocumentKey();
        EncryptedSearchSharingKey sharingKey = new EncryptedSearchSharingKey( documentKey );

        return sharingKey;
    }

    @Override
    public EncryptedSearchBridgeKey fromSharingKey( EncryptedSearchSharingKey sharingKey ) throws IrisException {
        try {
            return new EncryptedSearchBridgeKey( encryptedSearchPrivateKey, sharingKey );
        } catch ( SingularMatrixException e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public void submitBridgeKeyWithSearchNonce(
            DocumentId documentId,
            EncryptedSearchSharingKey sharingKey,
            BitVector searchNonce ) throws IrisException {

        try {
            dataStore.put(
                    ( documentId.getDocumentId() + EncryptedSearchSharingKey.class.getCanonicalName() ).getBytes(),
                    marshaller.toBytes( sharingKey ) );
            dataStore.put(
                    ( documentId.getDocumentId() + BitVector.class.getCanonicalName() ).getBytes(),
                    marshaller.toBytes( searchNonce ) );
        } catch ( IOException e1 ) {
            e1.printStackTrace();
        }

        BitVector encryptedSearchNonce = encryptNonce( searchNonce );
        EncryptedSearchBridgeKey bridgeKey = fromSharingKey( sharingKey );

        EncryptedSearchDocumentKey docKey = new EncryptedSearchDocumentKey( encryptedSearchNonce, bridgeKey, documentId );

        sharingClient.registerKeys( ImmutableSet.of( docKey ) );
    }

    @Override
    public BitVector encryptNonce( BitVector nonce ) {
        SimplePolynomialFunction encrypter = fhePublicKey.getEncrypter();
        return encrypter.apply( nonce, BitVectors.randomVector( nonce.size() ) );
    }

    @Override
    public BitVector generateIndexForToken( String token, BitVector searchNonce, EncryptedSearchSharingKey sharingKey )
            throws ResourceNotFoundException {
        BitVector searchHash = encryptedSearchPrivateKey.hash( token );
        BitVector searchToken = BitVectors.concatenate( searchHash, searchNonce );
        EnhancedBitMatrix expectedMatrix = EnhancedBitMatrix.squareMatrixfromBitVector( getGlobalHashFunction().apply(
                searchToken ) );
        BitVector indexForTerm = BitVectors.fromSquareMatrix( expectedMatrix.multiply( sharingKey.getMiddle() )
                .multiply( expectedMatrix ) );
        return indexForTerm;
    }

    @Override
    public BitVector prepareSearchToken( String token ) {
        return encryptedSearchPrivateKey.prepareSearchToken( fhePublicKey, token );
    }

    @Override
    public byte[] rsaDecrypt( byte[] ciphertext ) throws SecurityConfigurationException {
        return Cyphers.decrypt( RsaKeyLoader.CIPHER, securityService.getRsaPrivateKey(), ciphertext );
    }

    @Override
    public byte[] rsaEncrypt( byte[] plaintext ) throws SecurityConfigurationException {
        return Cyphers.encrypt( RsaKeyLoader.CIPHER, securityService.getRsaPublicKey(), plaintext );
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
        return new RsaCompressingCryptoService(
                RsaKeyLoader.CIPHER,
                securityService.getRsaPrivateKey(),
                securityService.getRsaPublicKey() );
    }
}
