package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.bitwise.BitVectors;
import com.kryptnostic.crypto.EncryptedSearchBridgeKey;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.EncryptedSearchSharingKey;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.linear.EnhancedBitMatrix;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.sharing.v1.models.PairedEncryptedSearchDocumentKey;
import com.kryptnostic.sharing.v1.requests.SharingApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.EncryptedSearchDocumentKey;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class DefaultKryptnosticContext implements KryptnosticContext {
    private final ObjectMapper              mapper;
    private final SharingApi                sharingClient;
    private final KeyApi                    keyClient;
    private final SearchFunctionApi         searchFunctionClient;
    private final PrivateKey                fhePrivateKey;
    private final PublicKey                 fhePublicKey;
    private final EncryptedSearchPrivateKey encryptedSearchPrivateKey;
    private final KryptnosticConnection     securityService;

    private SimplePolynomialFunction        globalHashFunction;
    private boolean                         queryHasherPairSubmitted;

    private static final Logger             logger          = LoggerFactory.getLogger( DefaultKryptnosticContext.class );

    private static final int                TOKEN_LENGTH    = 256;
    private static final int                LOCATION_LENGTH = 64;
    private static final int                NONCE_LENGTH    = 64;

    public DefaultKryptnosticContext(
            SearchFunctionApi searchFunctionClient,
            SharingApi sharingClient,
            KeyApi keyClient,
            KryptnosticConnection securityService ) throws IrisException, ResourceNotFoundException {
        this.searchFunctionClient = searchFunctionClient;
        this.sharingClient = sharingClient;
        this.keyClient = keyClient;
        this.securityService = securityService;

        Kodex<String> kodex = securityService.getKodex();
        if ( kodex == null ) {
            throw new IrisException(
                    "Security mapping was null and no keys could be found, the DefaultKryptnosticContext cannot be initialized without these keys" );
        }
        this.mapper = KodexObjectMapperFactory.getObjectMapper( kodex );

        try {
            this.fhePrivateKey = kodex.getKey(
                    PrivateKey.class.getCanonicalName(),
                    new JacksonKodexMarshaller<PrivateKey>( PrivateKey.class ) );

            this.fhePublicKey = kodex.getKey(
                    PublicKey.class.getCanonicalName(),
                    new JacksonKodexMarshaller<PublicKey>( PublicKey.class ) );

            if ( this.fhePrivateKey == null || this.fhePublicKey == null ) {
                throw new IrisException(
                        "FHE keys not found, the DefaultKryptnosticContext cannot be initialized without these keys" );
            }

        } catch ( InvalidKeyException e1 ) {
            throw new IrisException( e1 );
        } catch ( InvalidAlgorithmParameterException e1 ) {
            throw new IrisException( e1 );
        } catch ( NoSuchAlgorithmException e1 ) {
            throw new IrisException( e1 );
        } catch ( NoSuchPaddingException e1 ) {
            throw new IrisException( e1 );
        } catch ( InvalidKeySpecException e1 ) {
            throw new IrisException( e1 );
        } catch ( IllegalBlockSizeException e1 ) {
            throw new IrisException( e1 );
        } catch ( BadPaddingException e1 ) {
            throw new IrisException( e1 );
        } catch ( SealedKodexException e1 ) {
            throw new IrisException( e1 );
        } catch ( IOException e1 ) {
            throw new IrisException( e1 );
        }

        this.globalHashFunction = getGlobalHashFunction();

        EncryptedSearchPrivateKey storedSearchPrivateKey;
        try {
            storedSearchPrivateKey = kodex.getKeyWithJackson(
                    EncryptedSearchPrivateKey.class.getCanonicalName(),
                    EncryptedSearchPrivateKey.class );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }

        try {
            if ( storedSearchPrivateKey == null ) {
                this.encryptedSearchPrivateKey = new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHashFunction.getOutputLength() ) );
                kodex.setKeyWithJackson(
                        EncryptedSearchPrivateKey.class.getCanonicalName(),
                        storedSearchPrivateKey,
                        EncryptedSearchPrivateKey.class );
                securityService.flushKodex();
            } else {
                this.encryptedSearchPrivateKey = storedSearchPrivateKey;
            }
        } catch ( Exception e ) {
            throw new IrisException( e );
        }

        queryHasherPairSubmitted = false;
        ensureQueryHasherPairSet( globalHashFunction );
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
            globalHashFunction = this.searchFunctionClient.getFunction();
        }
        return globalHashFunction;
    }

    @Override
    public EncryptedSearchSharingKey generateSharingKey() {

        EnhancedBitMatrix documentKey = encryptedSearchPrivateKey.newDocumentKey();
        EncryptedSearchSharingKey sharingKey = new EncryptedSearchSharingKey( documentKey );

        return sharingKey;
    }

    private void ensureQueryHasherPairSet( SimplePolynomialFunction globalHashFunction ) throws IrisException,
            ResourceNotFoundException {
        if ( !queryHasherPairSubmitted ) {
            logger.debug( "Checking server if query hasher pair needs to be set" );
            queryHasherPairSubmitted = searchFunctionClient.hasQueryHasherPair().getData();

            if ( !queryHasherPairSubmitted ) {
                logger.debug( "Generating query hasher pair because it was not set on the server" );
                try {
                    Kodex<String> kodex = securityService.getKodex();
                    QueryHasherPairRequest qph = kodex.getKeyWithJackson(
                            QueryHasherPairRequest.class.getCanonicalName(),
                            QueryHasherPairRequest.class );
                    if ( qph == null ) {
                        Pair<SimplePolynomialFunction, SimplePolynomialFunction> queryHasherPair = encryptedSearchPrivateKey
                                .getQueryHasherPair( globalHashFunction, fhePrivateKey );
                        qph = new QueryHasherPairRequest( queryHasherPair.getLeft(), queryHasherPair.getRight() );
                        kodex.setKeyWithJackson(
                                QueryHasherPairRequest.class.getCanonicalName(),
                                qph,
                                QueryHasherPairRequest.class );
                    }
                    searchFunctionClient.setQueryHasherPair( qph );
                    queryHasherPairSubmitted = true;
                } catch ( Exception e1 ) {
                    logger.error( e1.getMessage() );
                    throw new IrisException( e1 );
                }
            }
        }
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
        EnhancedBitMatrix expectedMatrix = EnhancedBitMatrix.squareMatrixfromBitVector( getGlobalHashFunction().apply(
                BitVectors.concatenate( searchHash, searchNonce ) ) );
        BitVector indexForTerm = BitVectors.fromSquareMatrix( expectedMatrix.multiply( sharingKey.getMiddle() )
                .multiply( expectedMatrix ) );
        return indexForTerm;
    }
}
