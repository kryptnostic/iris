package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Stopwatch;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.crypto.v1.keys.PublicKeyAlgorithm;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.directory.v1.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.users.v1.UserKey;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger                     logger = LoggerFactory.getLogger( KryptnosticConnection.class );
    private final Kodex<String>                     kodex;
    private transient CryptoService                 cryptoService;
    private final UserKey                           userKey;
    private final String                            userCredential;
    private final String                            url;
    private final KeyApi                            keyService;
    private final DataStore                         dataStore;
    private final com.kryptnostic.crypto.PrivateKey fhePrivateKey;
    private final com.kryptnostic.crypto.PublicKey  fhePublicKey;

    public IrisConnection(
            Kodex<String> kodex,
            CryptoService cryptoService,
            UserKey userKey,
            String userCredential,
            String url ) throws IrisException {
        this.kodex = kodex;
        this.cryptoService = cryptoService;
        this.userKey = userKey;
        this.userCredential = userCredential;
        this.url = url;
        this.keyService = null;
        this.dataStore = null;
        try {
            fhePrivateKey = getFhePrivateKey( kodex );
            fhePublicKey = getFhePublicKey( kodex, fhePrivateKey );
            verifyOrSetCryptoService( kodex, cryptoService );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }
    }

    public IrisConnection( String url, UserKey userKey, String userCredential, DataStore dataStore ) throws IrisException {
        this.cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, userCredential.toCharArray() );
        keyService = KryptnosticRestAdapter.createWithDefaultJacksonConverter( url, userKey, userCredential ).create(
                KeyApi.class );

        this.userCredential = userCredential;
        this.userKey = userKey;
        this.url = url;

        try {
            PrivateKey privateKey = loadOrCreatePrivateKey( keyService, dataStore, cryptoService );
            PublicKey publicKey = loadOrCreatePublicKey( keyService, dataStore, cryptoService, userKey );
            kodex = loadOrCreateUnsealedKodex( keyService, dataStore, cryptoService, publicKey, privateKey );
            verifyOrSetCryptoService( kodex, cryptoService );
            fhePrivateKey = getFhePrivateKey( kodex );
            fhePublicKey = getFhePublicKey( kodex, fhePrivateKey );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }
        this.dataStore = dataStore;
    }

    @Override
    public String getUserCredential() {
        return userCredential;
    }

    @Override
    public UserKey getUserKey() {
        return userKey;
    }

    @Override
    public PrivateKey decryptPrivateKey( BlockCiphertext encryptedPrivateKey ) throws IrisException {
        try {
            return Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, cryptoService.decryptBytes( encryptedPrivateKey ) );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public BlockCiphertext encryptPrivateKey( PrivateKey privateKey ) throws IrisException {
        try {
            return cryptoService.encrypt( privateKey.getEncoded() );
        } catch ( Exception e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public void flushKodex() throws IOException {
        ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
        if ( dataStore != null ) {
            dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( kodex ) );
        }
        if ( keyService != null ) {
            keyService.setKodex( kodex );
        }
    }

    @Override
    public Kodex<String> getKodex() {
        return kodex;
    }

    @Override
    public String getUrl() {
        return url;
    }

    public static PrivateKey loadOrCreatePrivateKey( KeyApi keyService, DataStore dataStore, CryptoService crypto )
            throws IrisException {
        try {
            ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
            BlockCiphertext encryptedPrivateKey;
            Stopwatch watch = Stopwatch.createStarted();
            byte[] privateKeyCiphertext = dataStore.get( PrivateKey.class.getCanonicalName().getBytes() );
            logger.debug( "Time to load private key from disk: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
            if ( privateKeyCiphertext != null ) {
                watch.reset();
                watch.start();
                encryptedPrivateKey = mapper.readValue( privateKeyCiphertext, BlockCiphertext.class );
                logger.debug( "Time to load private key from disk: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
            } else {
                watch.reset();
                watch.start();
                encryptedPrivateKey = keyService.getPrivateKey();
                logger.debug( "Time to load private key from disk: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
                if ( encryptedPrivateKey == null ) {
                    KeyPair pair = Keys.generateRsaKeyPair( 1024 );
                    encryptedPrivateKey = crypto.encrypt( pair.getPrivate().getEncoded() );

                    watch.reset();
                    watch.start();
                    keyService.setPrivateKey( encryptedPrivateKey );
                    logger.debug( "Time to upload private key to service: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );

                    watch.reset();
                    watch.start();
                    keyService.setPublicKey( new PublicKeyEnvelope( pair.getPublic().getEncoded() ) );
                    logger.debug( "Time to upload public key to service: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );

                    watch.reset();
                    watch.start();
                    dataStore.put( PublicKey.class.getCanonicalName().getBytes(), pair.getPublic().getEncoded() );
                    logger.debug( "Time to write public key to file: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
                }
                watch.reset();
                watch.start();
                // Always write the private key to local storage
                dataStore.put(
                        PrivateKey.class.getCanonicalName().getBytes(),
                        mapper.writeValueAsBytes( encryptedPrivateKey ) );
                logger.debug( "Time to write private key to file: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
            }
            return Keys.privateKeyFromBytes( PublicKeyAlgorithm.RSA, crypto.decryptBytes( encryptedPrivateKey ) );
        } catch ( Exception e ) {
            wrapException( e );
            return null;
        }
    }

    public static PublicKey loadOrCreatePublicKey(
            KeyApi keyService,
            DataStore dataStore,
            CryptoService crypto,
            UserKey userKey ) throws IrisException {
        try {
            PublicKeyEnvelope envelope;
            byte[] publicKeyBytes = dataStore.get( PublicKey.class.getCanonicalName().getBytes() );
            if ( publicKeyBytes == null ) {
                envelope = keyService.getPublicKey( userKey.getRealm(), userKey.getName() );
                publicKeyBytes = envelope.getBytes();
                dataStore.put( PublicKey.class.getCanonicalName().getBytes(), publicKeyBytes );
            }
            return Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, publicKeyBytes );
        } catch ( Exception e ) {
            wrapException( e );
            return null;
        }
    }

    public static Kodex<String> loadOrCreateUnsealedKodex(
            KeyApi keyService,
            DataStore dataStore,
            CryptoService crypto,
            PublicKey publicKey,
            PrivateKey privateKey ) throws IrisException {
        Kodex<String> kodex;
        try {
            ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
            Stopwatch watch = Stopwatch.createStarted();
            byte[] kodexBytes = dataStore.get( Kodex.class.getCanonicalName().getBytes() );
            logger.debug( "Time to load kodex from disk: {} ,s", watch.elapsed( TimeUnit.MILLISECONDS ) );
            if ( kodexBytes != null ) {
                watch.reset();
                watch.start();
                kodex = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );
                logger.debug( "Time to deserialize kodex from disk: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
                kodex.verify( publicKey );
                kodex.unseal( privateKey );
            } else {
                watch.reset();
                watch.start();
                kodex = keyService.getKodex();
                logger.debug( "Time to load kodex from service: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
                if ( kodex == null ) {
                    kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_PKCS5_128, publicKey );
                    kodex.unseal( privateKey );
                    kodex.updateSignature();
                    kodex.verify( publicKey );
                }
                watch.reset();
                watch.start();
                dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( kodex ) );
                logger.debug( "Time to load kodex from service: {}", watch.elapsed( TimeUnit.MILLISECONDS ) );
            }
            return kodex;
        } catch ( Exception e ) {
            throw new IrisException( e );
        }
    }

    public static com.kryptnostic.crypto.PrivateKey getFhePrivateKey( Kodex<String> kodex ) throws InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, SealedKodexException, IOException {
        Stopwatch watch = Stopwatch.createStarted();
        com.kryptnostic.crypto.PrivateKey fhePrivateKey = kodex
                .getKey(
                        com.kryptnostic.crypto.PrivateKey.class.getCanonicalName(),
                        new JacksonKodexMarshaller<com.kryptnostic.crypto.PrivateKey>(
                                com.kryptnostic.crypto.PrivateKey.class ) );
        if ( fhePrivateKey == null ) {
            fhePrivateKey = new com.kryptnostic.crypto.PrivateKey( 128, 64 );
            logger.debug( "Time to generate new FHE private from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        } else {
            logger.debug( "Time to unmarshall FHE private from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        }
        return fhePrivateKey;
    }

    public static com.kryptnostic.crypto.PublicKey getFhePublicKey(
            Kodex<String> kodex,
            com.kryptnostic.crypto.PrivateKey privateKey ) throws InvalidKeyException,
            InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, SealedKodexException, IOException {
        Stopwatch watch = Stopwatch.createStarted();
        com.kryptnostic.crypto.PublicKey fhePublicKey = kodex.getKey(
                com.kryptnostic.crypto.PublicKey.class.getCanonicalName(),
                new JacksonKodexMarshaller<com.kryptnostic.crypto.PublicKey>( com.kryptnostic.crypto.PublicKey.class ) );
        if ( fhePublicKey == null ) {
            fhePublicKey = new com.kryptnostic.crypto.PublicKey( privateKey );
            logger.debug( "Time to generate new FHE public from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        } else {
            logger.debug( "Time to unmarshall FHE public from kodex: {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );
        }
        return fhePublicKey;
    }

    public static void verifyOrSetCryptoService( Kodex<String> kodex, CryptoService service )
            throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException,
            SealedKodexException, IOException, InvalidParameterSpecException, IrisException {
        CryptoService cs = kodex.getKeyWithJackson( CryptoService.class.getCanonicalName(), CryptoService.class );
        if ( cs == null ) {
            kodex.setKey( CryptoService.class.getCanonicalName(), new JacksonKodexMarshaller<CryptoService>(
                    CryptoService.class ), service );
        } else if ( !Arrays.equals( cs.getPassword(), service.getPassword() ) ) {
            throw new IrisException( "Crypto service mismatch-- password was changed without updating kodex properly." );
        }
    }

    public static void wrapException( Exception e ) throws IrisException {
        throw new IrisException( e );
    }

    @Override
    public com.kryptnostic.crypto.PrivateKey getPrivateKey() {
        return this.fhePrivateKey;
    }

    @Override
    public com.kryptnostic.crypto.PublicKey getPublicKey() {
        return this.fhePublicKey;
    }

}
