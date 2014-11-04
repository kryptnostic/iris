package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.client.Client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Preconditions;
import com.kryptnostic.api.v1.client.InMemoryStore;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.fhe.FreshKodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.KodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.LocalKodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.NetworkKodexLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.FreshRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.LocalRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.NetworkRsaKeyLoader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.directory.v1.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.utils.SimplePolynomialFunctionValidator;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;
import com.kryptnostic.users.v1.UserKey;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger                     logger = LoggerFactory.getLogger( IrisConnection.class );
    private final Kodex<String>                     kodex;
    private transient CryptoService                 cryptoService;
    private final UserKey                           userKey;
    private final String                            userCredential;
    private final String                            url;
    private final KeyApi                            keyService;
    private final DataStore                         dataStore;
    private final com.kryptnostic.crypto.PrivateKey fhePrivateKey;
    private final com.kryptnostic.crypto.PublicKey  fhePublicKey;
    private final EncryptedSearchPrivateKey         encryptedSearchPrivateKey;
    private final PublicKey                         rsaPublicKey;

    public IrisConnection(
            KeyPair keyPair,
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
        this.dataStore = new InMemoryStore();
        try {

            // loadRsaKeys( cryptoService, userKey, dataStore, keyService );
            this.rsaPublicKey = keyPair.getPublic();

            kodex.unseal( keyPair.getPublic(), keyPair.getPrivate() );

            this.fhePrivateKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            this.fhePublicKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            this.encryptedSearchPrivateKey = kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
        } catch ( KodexException | SecurityConfigurationException | CorruptKodexException e ) {
            throw new IrisException( e );
        }
    }

    public IrisConnection( String url, UserKey userKey, String userCredential, DataStore dataStore, Client client ) throws IrisException {
        this.cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, userCredential.toCharArray() );
        RestAdapter adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter(
                url,
                userKey,
                userCredential,
                client );
        this.keyService = adapter.create( KeyApi.class );
        final SearchFunctionApi searchFunctionService = adapter.create( SearchFunctionApi.class );

        ExecutorService exec = Executors.newCachedThreadPool();

        logger.debug( "Submitting async call for global hasher" );
        Future<SimplePolynomialFunction> hashGetter = exec.submit( new Callable<SimplePolynomialFunction>() {
            @Override
            public SimplePolynomialFunction call() {
                try {
                    SimplePolynomialFunction gh = searchFunctionService.getFunction();
                    logger.debug( "Done with async call for global hasher" );
                    return gh;
                } catch ( ResourceNotFoundException e ) {
                    logger.error( "Global hasher request failed {}", e );
                    e.printStackTrace();
                }
                return null;
            }

        } );

        this.userCredential = userCredential;
        this.userKey = userKey;
        this.url = url;
        this.dataStore = dataStore;

        logger.debug( "Loading RSA keys" );
        KeyPair keyPair = loadRsaKeys( cryptoService, userKey, dataStore, keyService );

        this.rsaPublicKey = keyPair.getPublic();

        SimplePolynomialFunction globalHashFunction;
        try {
            globalHashFunction = hashGetter.get();
        } catch ( InterruptedException | ExecutionException e ) {
            throw new IrisException( e );
        }

        Kodex<String> searchKodex = loadSearchKodex(
                dataStore,
                keyPair,
                keyService,
                searchFunctionService,
                globalHashFunction );

        // TODO: insert document keyring/kodex here!
        this.kodex = searchKodex;

        try {
            Future<com.kryptnostic.crypto.PrivateKey> fhePrivateKeyGetter = asynchronousKodexLoad(
                    searchKodex,
                    com.kryptnostic.crypto.PrivateKey.class,
                    exec );
            Future<com.kryptnostic.crypto.PublicKey> fhePublicKeyGetter = asynchronousKodexLoad(
                    searchKodex,
                    com.kryptnostic.crypto.PublicKey.class,
                    exec );
            Future<com.kryptnostic.crypto.EncryptedSearchPrivateKey> encryptedSearchPrivateKeyGetter = asynchronousKodexLoad(
                    searchKodex,
                    com.kryptnostic.crypto.EncryptedSearchPrivateKey.class,
                    exec );

            this.kodex.setKeyWithClassAndJackson( CryptoService.class, cryptoService );
            String qhpChecksum = searchKodex.getKeyWithJackson(
                    QueryHasherPairRequest.class.getCanonicalName(),
                    String.class );

            logger.debug( "Getting QHP checksum..." );
            String checksum = searchFunctionService.getQueryHasherChecksum().getData();
            logger.debug( "Done getting QHP checksum." );

            Preconditions.checkState( qhpChecksum.equals( checksum ) );

            this.fhePrivateKey = fhePrivateKeyGetter.get();
            this.fhePublicKey = fhePublicKeyGetter.get();
            this.encryptedSearchPrivateKey = encryptedSearchPrivateKeyGetter.get();

        } catch (
                KodexException
                | SecurityConfigurationException
                | SealedKodexException
                | InterruptedException
                | ExecutionException e ) {
            throw new IrisException( e );
        }
    }

    private <T> Future<T> asynchronousKodexLoad( final Kodex<String> kodex, final Class<T> key, ExecutorService exec ) {
        return exec.submit( new Callable<T>() {
            @Override
            public T call() {
                try {
                    return kodex.getKeyWithJackson( key );
                } catch ( KodexException | SecurityConfigurationException e ) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                return null;
            }
        } );
    }

    private KeyPair loadRsaKeys( CryptoService crypto, UserKey userKey, DataStore dataStore, KeyApi keyClient )
            throws IrisException {
        KeyPair keyPair = null;

        try {
            logger.debug( "Loading RSA keys from disk" );
            keyPair = new LocalRsaKeyLoader( crypto, dataStore ).load();
        } catch ( KodexException e ) {
            logger.debug( "Could not load RSA keys from disk, trying network... {}", e );
        }
        if ( keyPair == null ) {
            try {
                logger.debug( "Loading RSA keys from network" );
                keyPair = new NetworkRsaKeyLoader( crypto, keyClient, userKey ).load();
                try {
                    flushRsaKeysToDisk( keyPair, createEncryptedPrivateKey( keyPair ) );
                } catch ( IOException | SecurityConfigurationException e ) {
                    e.printStackTrace();
                }
            } catch ( KodexException e ) {
                logger.debug( "Could not load RSA keys from network, trying to generate... {}", e );
            }
        }
        if ( keyPair == null ) {
            try {
                logger.debug( "Generating RSA keys" );
                keyPair = new FreshRsaKeyLoader().load();
                try {
                    BlockCiphertext encPrivKey = createEncryptedPrivateKey( keyPair );
                    flushRsaKeysToDisk( keyPair, encPrivKey );
                    flushRsaKeysToWeb( keyPair, encPrivKey );
                } catch ( IOException | SecurityConfigurationException e ) {
                    e.printStackTrace();
                }
            } catch ( KodexException e ) {
                logger.debug( "Could not generate RSA Keys! {}", e );
            }
        }
        if ( keyPair == null ) {
            throw new IrisException( "Could not load RSA Keys" );
        }
        return keyPair;
    }

    private BlockCiphertext createEncryptedPrivateKey( KeyPair keyPair ) throws SecurityConfigurationException {
        logger.debug( "Encrypting private key..." );
        BlockCiphertext encPrivKey = cryptoService.encrypt( keyPair.getPrivate().getEncoded() );
        logger.debug( "Done encrypting private key." );

        return encPrivKey;
    }

    private void flushRsaKeysToWeb( KeyPair keyPair, BlockCiphertext encPrivKey ) {
        byte[] pubKey = keyPair.getPublic().getEncoded();

        logger.debug( "Flushing RSA privkey to web..." );
        keyService.setPrivateKey( encPrivKey );
        logger.debug( "Done flushing RSA privkey to web." );

        logger.debug( "Flushing RSA pubkey to web..." );
        keyService.setPublicKey( new PublicKeyEnvelope( pubKey ) );
        logger.debug( "Done flushing RSA pubkey to web." );
    }

    private void flushRsaKeysToDisk( KeyPair keyPair, BlockCiphertext encPrivKey ) throws IOException {
        ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
        byte[] pubKey = keyPair.getPublic().getEncoded();

        // Flush to disk
        logger.debug( "Flushing RSA Private Key to disk..." );
        dataStore.put( PrivateKey.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( encPrivKey ) );
        logger.debug( "Done flushing RSA Private Key to disk." );

        logger.debug( "Flushing RSA pubkey to disk..." );
        dataStore.put( PublicKey.class.getCanonicalName().getBytes(), pubKey );
        logger.debug( "Done flushing RSA pubkey to disk..." );
    }

    private Kodex<String> loadSearchKodex(
            DataStore dataStore,
            KeyPair keyPair,
            KeyApi keyService,
            SearchFunctionApi searchFunctionService,
            SimplePolynomialFunction globalHashFunction ) throws IrisException {

        Kodex<String> searchKodex = null;
        try {
            logger.debug( "Loading kodex from disk" );
            searchKodex = new LocalKodexLoader( keyPair, dataStore ).load();
        } catch ( KodexException e ) {
            logger.debug( "Could not load Kodex from disk, trying network... {}", e );
        }
        if ( searchKodex == null ) {
            try {
                logger.debug( "Loading kodex from network" );
                searchKodex = new NetworkKodexLoader( keyPair, keyService ).load();
                try {
                    flushKodexToDisk( searchKodex );
                } catch ( IOException e ) {
                    e.printStackTrace();
                }
            } catch ( KodexException e ) {
                logger.debug( "Could not load Kodex from network, trying to generate... {}", e );
            }
        }
        if ( searchKodex == null ) {
            try {
                logger.debug( "Generating Kodex" );
                searchKodex = new FreshKodexLoader( keyPair, globalHashFunction, searchFunctionService, dataStore )
                        .load();
                try {
                    flushKodexToDisk( searchKodex );
                } catch ( IOException e ) {
                    e.printStackTrace();
                }
                flushKodexToWeb( searchKodex );
            } catch ( KodexException e ) {
                logger.debug( "Could not generate Kodex! {}", e );
            }
        }
        if ( searchKodex == null ) {
            throw new IrisException( "Could not load Kodex" );
        }
        return searchKodex;
    }

    private void flushKodexToWeb( Kodex<String> searchKodex ) {
        logger.debug( "Flushing kodex to web..." );
        keyService.setKodex( searchKodex );
        logger.debug( "Done flushing kodex to web." );
    }

    private void flushKodexToDisk( Kodex<String> searchKodex ) throws JsonProcessingException, IOException {
        ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
        logger.debug( "Flushing Kodex to disk..." );
        dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( searchKodex ) );
        logger.debug( "Done flushing Kodex to disk." );
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
    public Kodex<String> getKodex() {
        return kodex;
    }

    @Override
    public String getUrl() {
        return url;
    }

    public Kodex<String> getCryptoKodex() throws IrisException {
        Kodex<String> kodex;
        try {
            kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_PKCS5_128, this.rsaPublicKey );
            kodex.setKey( CryptoService.class.getCanonicalName(), new JacksonKodexMarshaller<CryptoService>(
                    CryptoService.class ), this.cryptoService );
            return kodex;
        } catch (
                InvalidKeyException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | SignatureException
                | JsonProcessingException
                | SecurityConfigurationException
                | SealedKodexException
                | KodexException e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public com.kryptnostic.crypto.PrivateKey getFhePrivateKey() {
        return this.fhePrivateKey;
    }

    @Override
    public com.kryptnostic.crypto.PublicKey getFhePublicKey() {
        return this.fhePublicKey;
    }

    @Override
    public EncryptedSearchPrivateKey getEncryptedSearchPrivateKey() {
        return encryptedSearchPrivateKey;
    }

    @Override
    public DataStore getDataStore() {
        return dataStore;
    }

    private SimplePolynomialFunctionValidator[] getValidators() throws IrisException {
        try {
            byte[] leftValidator = dataStore.get( KodexLoader.LEFT_VALIDATOR );
            byte[] rightValidator = dataStore.get( KodexLoader.RIGHT_VALIDATOR );

            if ( leftValidator == null || rightValidator == null ) {
                return null;
            }

            return new SimplePolynomialFunctionValidator[] {
                    SimplePolynomialFunctionValidator.fromBytes( leftValidator ),
                    SimplePolynomialFunctionValidator.fromBytes( rightValidator ) };
        } catch ( IOException e ) {
            throw new IrisException( e );
        }
    }
}
