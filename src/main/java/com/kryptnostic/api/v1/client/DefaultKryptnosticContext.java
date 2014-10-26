package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Stopwatch;
import com.google.common.collect.Lists;
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
        Stopwatch watch = Stopwatch.createStarted();
        try {
            this.fhePrivateKey = kodex.getKey(
                    PrivateKey.class.getCanonicalName(),
                    new JacksonKodexMarshaller<PrivateKey>( PrivateKey.class ) );
            logger.debug( "Time to unmarshall FHE private from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
            watch.reset();
            watch.start();
            this.fhePublicKey = kodex.getKey(
                    PublicKey.class.getCanonicalName(),
                    new JacksonKodexMarshaller<PublicKey>( PublicKey.class ) );
            logger.debug( "Time to unmarshall FHE public from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
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
        watch.reset();
        watch.start();
        this.globalHashFunction = getGlobalHashFunction();
        logger.debug( "Time to download global hash function from server: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        EncryptedSearchPrivateKey storedSearchPrivateKey;
        try {
            watch.reset();
            watch.start();
            storedSearchPrivateKey = kodex.getKeyWithJackson(
                    EncryptedSearchPrivateKey.class.getCanonicalName(),
                    EncryptedSearchPrivateKey.class );
            logger.debug(
                    "Time to deserialize encrypted search private key from kodex: {} ms",
                    watch.elapsed( TimeUnit.MILLISECONDS ) );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }

        try {
            if ( storedSearchPrivateKey == null ) {
                watch.reset();
                watch.start();
                this.encryptedSearchPrivateKey = new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHashFunction
                        .getOutputLength() ) );
                logger.debug(
                        "Time to generate new encrypted search private: {} ms",
                        watch.elapsed( TimeUnit.MILLISECONDS ) );

                watch.reset();
                watch.start();
                kodex.setKeyWithJackson(
                        EncryptedSearchPrivateKey.class.getCanonicalName(),
                        storedSearchPrivateKey,
                        EncryptedSearchPrivateKey.class );
                logger.debug(
                        "Time to serialized new encrypted search private to kodex: {} ms",
                        watch.elapsed( TimeUnit.MILLISECONDS ) );
                watch.reset();

            } else {
                this.encryptedSearchPrivateKey = storedSearchPrivateKey;
            }
        } catch ( Exception e ) {
            throw new IrisException( e );
        }

        queryHasherPairSubmitted = false;
        ensureQueryHasherPairSet( globalHashFunction );
        try {
            watch.start();
            securityService.flushKodex();
            logger.debug(
                    "Time to flush kodex after writing new encrypted search private: {} ms",
                    watch.elapsed( TimeUnit.MILLISECONDS ) );
        } catch ( IOException e ) {
            throw new IrisException( e );
        }
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
        Stopwatch watch = Stopwatch.createStarted();
        if ( !queryHasherPairSubmitted ) {
            logger.debug( "Checking server if query hasher pair needs to be set" );
            queryHasherPairSubmitted = searchFunctionClient.hasQueryHasherPair().getData();
            logger.debug( "Time to check for query hasher pair: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
            watch.reset();
            if ( !queryHasherPairSubmitted ) {
                logger.debug( "Generating query hasher pair because it was not set on the server" );
                try {
                    Kodex<String> kodex = securityService.getKodex();
                    logger.info( "Attempting to retreive query hasher pair from kodex." );
                    watch.start();
                    QueryHasherPairRequest qph = kodex.getKeyWithJackson(
                            QueryHasherPairRequest.class.getCanonicalName(),
                            QueryHasherPairRequest.class );
                    logger.debug(
                            "Time to deserialize query hash pair from kodex: {} ms",
                            watch.elapsed( TimeUnit.MILLISECONDS ) );
                    watch.reset();
                    if ( qph == null ) {
                        watch.start();
                        Pair<SimplePolynomialFunction, SimplePolynomialFunction> queryHasherPair = encryptedSearchPrivateKey
                                .getQueryHasherPair( globalHashFunction, fhePrivateKey );
                        logger.debug(
                                "Time to generate new query hasher pair: {} ms",
                                watch.elapsed( TimeUnit.MILLISECONDS ) );
                        watch.reset();
                        qph = new QueryHasherPairRequest( queryHasherPair.getLeft(), queryHasherPair.getRight() );
                        watch.start();
                        kodex.setKeyWithJackson(
                                QueryHasherPairRequest.class.getCanonicalName(),
                                qph,
                                QueryHasherPairRequest.class );
                        logger.debug(
                                "Time to write new query hash pair into kodex: {} ms",
                                watch.elapsed( TimeUnit.MILLISECONDS ) );
                        watch.reset();
                    }
                    watch.start();
                    searchFunctionClient.setQueryHasherPair( qph );
                    logger.debug(
                            "Time to upload new queryHasherPair to service: {} ms",
                            watch.elapsed( TimeUnit.MILLISECONDS ) );
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

    @Override
    public BitVector prepareSearchToken( String token ) throws IrisException {
        try {
            return encryptedSearchPrivateKey.prepareSearchToken( fhePublicKey, token );
        } catch ( SingularMatrixException e ) {
            throw new IrisException( e );
        }
    }
}
