package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.client.Client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Stopwatch;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.fhe.FreshKodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.KodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.LocalKodexLoader;
import com.kryptnostic.api.v1.security.loaders.fhe.NetworkKodexLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.FreshRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.LocalRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.NetworkRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.directory.v1.principal.UserKey;
import com.kryptnostic.kodex.v1.authentication.CredentialFactory;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.crypto.keys.DefaultCryptoServiceLoader;
import com.kryptnostic.kodex.v1.crypto.keys.JacksonKodexMarshaller;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.utils.SimplePolynomialFunctionValidator;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.http.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger               logger         = LoggerFactory.getLogger( IrisConnection.class );
    private Kodex<String>                     kodex;
    private transient PasswordCryptoService   cryptoService;
    private final UserKey                     userKey;
    private final String                      userCredential;
    private final String                      url;
    private final DirectoryApi                keyService;
    private final DataStore                   dataStore;
    private com.kryptnostic.crypto.PrivateKey fhePrivateKey;
    private com.kryptnostic.crypto.PublicKey  fhePublicKey;
    private EncryptedSearchPrivateKey         encryptedSearchPrivateKey;
    private final PublicKey                   rsaPublicKey;
    private final PrivateKey                  rsaPrivateKey;
    private final CryptoServiceLoader         loader;
    boolean                                   doFresh        = false;
    private final SearchFunctionApi           searchFunctionService;
    private SimplePolynomialFunction          globalHashFunction;
    private final AtomicBoolean               isKodexLoaded  = new AtomicBoolean( false );
    private final AtomicBoolean               isKodexLoading = new AtomicBoolean( false );

    private Future<SimplePolynomialFunction>  hashGetter;

    public IrisConnection( String url, UserKey userKey, String userCredential, DataStore dataStore, Client client ) throws IrisException {
        this( url, userKey, userCredential, dataStore, client, null, null );
    }

    public IrisConnection(
            String url,
            UserKey userKey,
            String password,
            DataStore dataStore,
            Client client,
            Kodex<String> kodex,
            KeyPair keyPair ) throws IrisException {

        RestAdapter bootstrap = KryptnosticRestAdapter.createWithNoAuthAndDefaultJacksonConverter( url, client );
        BlockCiphertext encryptedSalt = bootstrap.create( DirectoryApi.class ).getSalt();
        String credential;
        try {
            credential = CredentialFactory.deriveCredential( password, encryptedSalt );
        } catch ( SecurityConfigurationException | InvalidKeySpecException | NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        }

        RestAdapter adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter(
                url,
                userKey,
                credential,
                client );
        this.keyService = adapter.create( DirectoryApi.class );
        this.searchFunctionService = adapter.create( SearchFunctionApi.class );

        ExecutorService exec = Executors.newCachedThreadPool();

        logger.debug( "Submitting async call for global hasher" );
        hashGetter = exec.submit( new Callable<SimplePolynomialFunction>() {
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

        this.userCredential = credential;
        this.userKey = userKey;
        this.url = url;
        this.dataStore = dataStore;
        this.kodex = kodex;

        /**
         * Load basic RSA keys into connection or generate them
         */
        Stopwatch watch = Stopwatch.createStarted();
        if ( keyPair == null ) {
            keyPair = loadRsaKeys( cryptoService, userKey, dataStore, keyService );
        }
        this.rsaPrivateKey = keyPair.getPrivate();
        this.rsaPublicKey = keyPair.getPublic();
        logger.debug( "[PROFILE] load rsa keys {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        this.loader = new DefaultCryptoServiceLoader( this, keyService, Cypher.AES_CTR_128 );
    }

    private KeyPair loadRsaKeys(
            PasswordCryptoService crypto,
            UserKey userKey,
            DataStore dataStore,
            DirectoryApi keyClient ) throws IrisException {
        KeyPair keyPair = null;

        try {
            logger.debug( "Loading RSA keys from disk" );
            keyPair = new LocalRsaKeyLoader( crypto, keyClient, dataStore ).load();
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
        dataStore.put( PrivateKey.class.getCanonicalName(), mapper.writeValueAsBytes( encPrivKey ) );
        logger.debug( "Done flushing RSA Private Key to disk." );

        logger.debug( "Flushing RSA pubkey to disk..." );
        dataStore.put( PublicKey.class.getCanonicalName(), pubKey );
        logger.debug( "Done flushing RSA pubkey to disk..." );
    }

    private Kodex<String> loadSearchKodex(
            DataStore dataStore,
            KeyPair keyPair,
            DirectoryApi keyService,
            SearchFunctionApi searchFunctionService,
            SimplePolynomialFunction globalHashFunction ) throws IrisException {

        Kodex<String> searchKodex = null;
        try {
            logger.debug( "Loading kodex from disk" );
            searchKodex = new LocalKodexLoader( keyPair, dataStore ).load();
        } catch ( KodexException e ) {
            logger.debug( "Could not load Kodex from disk, trying network... {}", e.getMessage() );
        }
        if ( searchKodex == null ) {
            try {
                logger.debug( "Loading kodex from network" );
                searchKodex = new NetworkKodexLoader( keyPair, keyService ).load();
                try {
                    flushKodexToDisk( searchKodex );
                } catch ( IOException e ) {
                    logger.error( "Couldn't flush Kodex to disk {}", e );
                }
            } catch ( KodexException e ) {
                logger.debug( "Could not load Kodex from network, trying to generate... {}", e.getMessage() );
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
                    logger.error( "Couldn't flush Kodex to disk {}", e );
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
        dataStore.put( Kodex.class.getCanonicalName(), mapper.writeValueAsBytes( searchKodex ) );
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
    public String getUrl() {
        return url;
    }

    public Kodex<String> getCryptoKodex() throws IrisException {
        Kodex<String> kodex;
        try {
            kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_4096, Cypher.AES_CTR_128, this.rsaPublicKey );
            kodex.setKey(
                    PasswordCryptoService.class.getCanonicalName(),
                    new JacksonKodexMarshaller<PasswordCryptoService>( PasswordCryptoService.class ),
                    this.cryptoService );
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
    public Kodex<String> getKodex() {
        ensureKodexLoaded();
        return kodex;
    }

    @Override
    public com.kryptnostic.crypto.PrivateKey getFhePrivateKey() {
        ensureKodexLoaded();
        return this.fhePrivateKey;
    }

    @Override
    public com.kryptnostic.crypto.PublicKey getFhePublicKey() {
        ensureKodexLoaded();
        return this.fhePublicKey;
    }

    @Override
    public EncryptedSearchPrivateKey getEncryptedSearchPrivateKey() {
        ensureKodexLoaded();
        return encryptedSearchPrivateKey;
    }

    private void ensureKodexLoaded() {
        while ( !isKodexLoaded.get() ) {
            try {
                loadKodex();
            } catch ( IrisException e ) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            try {
                Thread.sleep( 1 );
            } catch ( InterruptedException e ) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    @Override
    public DataStore getDataStore() {
        return dataStore;
    }

    @Override
    public PrivateKey getRsaPrivateKey() {
        return rsaPrivateKey;
    }

    @Override
    public PublicKey getRsaPublicKey() {
        return rsaPublicKey;
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

    @Override
    public CryptoServiceLoader getCryptoServiceLoader() {
        return loader;
    }

    @Override
    public RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException {
        return new RsaCompressingCryptoService( RsaKeyLoader.CIPHER, getRsaPrivateKey(), getRsaPublicKey() );
    }

    @Override
    public boolean isKodexReady() {
        return isKodexLoaded.get() && kodex != null && fhePrivateKey != null && fhePublicKey != null
                && encryptedSearchPrivateKey != null;
    }

    @Override
    public Kodex<String> loadKodex() throws IrisException {
        if ( !isKodexLoaded.get() && !isKodexLoading.getAndSet( true ) ) {
            Stopwatch watch = Stopwatch.createStarted();
            /**
             * Load kodex related information into IrisConnection or generate it
             */
            if ( kodex == null ) {
                if ( globalHashFunction == null ) {
                    try {
                        globalHashFunction = hashGetter.get();
                    } catch ( InterruptedException | ExecutionException e ) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
                kodex = loadSearchKodex(
                        dataStore,
                        new KeyPair( rsaPublicKey, rsaPrivateKey ),
                        keyService,
                        searchFunctionService,
                        globalHashFunction );
            }

            try {
                this.kodex.setKeyWithClassAndJackson( PasswordCryptoService.class, cryptoService );
                watch.reset().start();
                String qhpChecksum = this.kodex.getKeyWithJackson(
                        QueryHasherPairRequest.class.getCanonicalName(),
                        String.class );

                String checksum = searchFunctionService.getQueryHasherChecksum().getData();
                logger.debug( "[PROFILE] getting QHP checksum {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

                if ( !qhpChecksum.equals( checksum ) ) {
                    try {
                        dataStore.delete( Kodex.class.getCanonicalName() );
                        dataStore.delete( PrivateKey.class.getCanonicalName() );
                        dataStore.delete( PublicKey.class.getCanonicalName() );
                    } catch ( IOException e ) {
                        logger.error( "Could not delete Kodex" );
                        e.printStackTrace();
                    }
                    throw new KodexException( "QHP failed checksum validation" );
                }

                watch.reset().start();
                this.fhePrivateKey = this.kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
                this.fhePublicKey = this.kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
                this.encryptedSearchPrivateKey = this.kodex
                        .getKeyWithJackson( com.kryptnostic.crypto.EncryptedSearchPrivateKey.class );
                logger.debug( "[PROFILE] unmarshal Kodex objects {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

                isKodexLoaded.set( true );
            } catch ( SealedKodexException | KodexException | SecurityConfigurationException e ) {
                // TODO Auto-generated catch block
                e.printStackTrace();
                throw new IrisException( e );
            }
        }
        return kodex;
    }
}
