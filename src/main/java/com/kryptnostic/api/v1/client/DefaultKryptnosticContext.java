package com.kryptnostic.api.v1.client;

import java.io.IOException;

import org.apache.commons.codec.binary.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.linear.EnhancedBitMatrix;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.sharing.v1.models.PairedEncryptedSearchDocumentKey;
import com.kryptnostic.sharing.v1.requests.SharingApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final ObjectMapper              mapper          = KodexObjectMapperFactory.getObjectMapper();
    private final SharingApi                sharingClient;
    private final KeyApi                    keyClient;
    private final SearchFunctionApi         searchFunctionClient;
    private final PrivateKey                fhePrivateKey;
    private final PublicKey                 fhePublicKey;
    private final EncryptedSearchPrivateKey encryptedSearchPrivateKey;
    private final KryptnosticConnection     securityService;
    private final DataStore                 dataStore;
    private SimplePolynomialFunction        globalHashFunction;

    public static final String              CHECKSUM_KEY    = "global-hash-checksum";
    public static final String              FUNCTION_KEY    = "global-hash-function";

    private static final Logger             logger          = LoggerFactory.getLogger( DefaultKryptnosticContext.class );

    private static final int                TOKEN_LENGTH    = 256;
    private static final int                LOCATION_LENGTH = 64;
    private static final int                NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext(
            SearchFunctionApi searchFunctionClient,
            SharingApi sharingClient,
            KeyApi keyClient,
            KryptnosticConnection securityService ) throws IrisException {
        this.searchFunctionClient = searchFunctionClient;
        this.sharingClient = sharingClient;
        this.keyClient = keyClient;
        this.securityService = securityService;
        this.fhePublicKey = securityService.getFhePublicKey();
        this.fhePrivateKey = securityService.getFhePrivateKey();
        this.encryptedSearchPrivateKey = securityService.getEncryptedSearchPrivateKey();
        this.dataStore = securityService.getDataStore();
    }

    @Override
    public KryptnosticConnection getSecurityService() {
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
    public void submitBridgeKeyWithSearchNonce(
            DocumentId documentId,
            EncryptedSearchSharingKey sharingKey,
            BitVector searchNonce ) throws IrisException {
        BitVector encryptedSearchNonce = encryptNonce( searchNonce );
        try {
            EncryptedSearchBridgeKey bridgeKey = new EncryptedSearchBridgeKey( encryptedSearchPrivateKey, sharingKey );

            EncryptedSearchDocumentKey docKey = new EncryptedSearchDocumentKey( encryptedSearchNonce, bridgeKey );

            // TODO: IMPORTANT: encrypt this with user's public rsa key
            byte[] notEncryptedDocumentId_CHANGE_ME = mapper.writeValueAsBytes( documentId );

            PairedEncryptedSearchDocumentKey pairedKey = new PairedEncryptedSearchDocumentKey(
                    notEncryptedDocumentId_CHANGE_ME,
                    docKey );
            sharingClient.registerKeys( Lists.newArrayList( pairedKey ) );
        } catch ( SingularMatrixException e ) {
            throw new IrisException( e );
        } catch ( JsonProcessingException e ) {
            throw new IrisException( e );
        }
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

        // QueryHasherPairRequest req = null;
        // SimplePolynomialFunction lh = null;
        // SimplePolynomialFunction rh = null;
        // Pair<SimplePolynomialFunction, SimplePolynomialFunction> p = null;
        // try {
        // p = encryptedSearchPrivateKey.getQueryHasherPair(
        // globalHashFunction,
        // fhePrivateKey );
        // req = securityService.getKodex().getKeyWithJackson( QueryHasherPairRequest.class );
        // lh = req.getLeft();
        // rh = req.getRight();
        // Preconditions.checkState( p.getLeft().equals( lh ) );
        // Preconditions.checkState( p.getRight().equals( rh ) );
        // } catch ( SecurityConfigurationException | KodexException e ) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // } catch ( IOException e ) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // } catch ( SingularMatrixException e ) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }
        //
        // BitVector t = prepareSearchToken( token );
        // BitVector simulatedSearchToken = BitVectors.concatenate(
        // t,
        // fhePublicKey.getEncrypter().apply( searchNonce, BitVectors.randomVector( searchNonce.size() ) ) );
        // EnhancedBitMatrix lv = EnhancedBitMatrix.squareMatrixfromBitVector( lh.apply( simulatedSearchToken ) );
        // EnhancedBitMatrix rv = EnhancedBitMatrix.squareMatrixfromBitVector( rh.apply( simulatedSearchToken ) );
        //
        // EnhancedBitMatrix bridge = null;
        // try {
        // Preconditions.checkState( lv.multiply( encryptedSearchPrivateKey.getLeftSquaringMatrix().inverse() )
        // .equals( expectedMatrix ) );
        // Preconditions.checkState( encryptedSearchPrivateKey.getRightSquaringMatrix().inverse().multiply( rv )
        // .equals( expectedMatrix ) );
        // bridge = new EncryptedSearchBridgeKey( encryptedSearchPrivateKey, sharingKey ).getBridge();
        // } catch ( SingularMatrixException e1 ) {
        // e1.printStackTrace();
        // }
        //
        // lh = p.getLeft();
        // rh = p.getRight();
        // lv = EnhancedBitMatrix.squareMatrixfromBitVector( lh.apply( simulatedSearchToken ) );
        // rv = EnhancedBitMatrix.squareMatrixfromBitVector( rh.apply( simulatedSearchToken ) );
        // try {
        // Preconditions.checkState( lv.multiply( encryptedSearchPrivateKey.getLeftSquaringMatrix().inverse() )
        // .equals( expectedMatrix ) );
        // Preconditions.checkState( encryptedSearchPrivateKey.getRightSquaringMatrix().inverse().multiply( rv )
        // .equals( expectedMatrix ) );
        // bridge = new EncryptedSearchBridgeKey( encryptedSearchPrivateKey, sharingKey ).getBridge();
        // } catch ( SingularMatrixException e1 ) {
        // e1.printStackTrace();
        // }
        //
        // Preconditions.checkState( encryptedSearchPrivateKey.getLeftSquaringMatrix()
        // .multiply( bridge.multiply( encryptedSearchPrivateKey.getRightSquaringMatrix() ) )
        // .equals( sharingKey.getMiddle() ) );
        //
        // BitVector actual = BitVectors.fromSquareMatrix( lv.multiply( bridge ).multiply( rv ) );
        // try {
        // Preconditions.checkState( indexForTerm.equals( actual ) );
        // Preconditions.checkState( lv.multiply( encryptedSearchPrivateKey.getLeftSquaringMatrix().inverse() )
        // .equals( expectedMatrix ) );
        // Preconditions.checkState( encryptedSearchPrivateKey.getRightSquaringMatrix().inverse().multiply( rv )
        // .equals( expectedMatrix ) );
        // } catch ( SingularMatrixException e ) {
        // // TODO Auto-generated catch block
        // e.printStackTrace();
        // }

        return indexForTerm;
    }

    @Override
    public BitVector prepareSearchToken( String token ) {
        return encryptedSearchPrivateKey.prepareSearchToken( fhePublicKey, token );
    }
}
