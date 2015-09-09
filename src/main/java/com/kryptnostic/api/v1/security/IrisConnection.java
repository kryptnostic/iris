package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.client.Client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.rsa.FreshRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.LocalRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.NetworkRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.authentication.CredentialFactory;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.crypto.keys.DefaultCryptoServiceLoader;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.storage.v1.http.CryptoKeyStorageApi;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger                   logger                     = LoggerFactory
                                                                                     .getLogger( IrisConnection.class );
    private transient final PasswordCryptoService cryptoService;
    private final UUID                            userKey;
    private final String                          userCredential;
    private final String                          url;
    private final DirectoryApi                    keyService;
    private final CryptoKeyStorageApi             cryptoKeyStorageApi;
    private final DataStore                       dataStore;
    private final PublicKey                       rsaPublicKey;
    private final PrivateKey                      rsaPrivateKey;
    private final CryptoServiceLoader             loader;
    boolean                                       doFresh                    = false;
    private final KryptnosticEngine               engine;

    public IrisConnection( String url, UUID userKey, String password, DataStore dataStore, Client client ) throws IrisException {
        this( url, userKey, password, dataStore, client, null );
    }

    public IrisConnection(
            String url,
            UUID userKey,
            String password,
            DataStore dataStore,
            Client client,
            KeyPair keyPair ) throws IrisException {
        cryptoService = new PasswordCryptoService( password );
        String credential = bootstrapCredential( userKey, url, password, client );

        RestAdapter adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter(
                url,
                userKey,
                credential,
                client );

        this.keyService = adapter.create( DirectoryApi.class );
        this.cryptoKeyStorageApi = adapter.create( CryptoKeyStorageApi.class );

        this.userCredential = credential;
        this.userKey = userKey;
        this.url = url;
        this.dataStore = dataStore;

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
        this.engine = loadEngine();
    }

    private static String bootstrapCredential( UUID userKey, String url, String password, Client client )
            throws IrisException {
        RestAdapter bootstrap = KryptnosticRestAdapter.createWithNoAuthAndDefaultJacksonConverter( url, client );
        BlockCiphertext encryptedSalt = null;
        try {
            encryptedSalt = bootstrap.create( DirectoryApi.class ).getSalt( userKey );
        } catch ( ResourceNotFoundException e1 ) {}

        if ( encryptedSalt == null ) {
            throw new IrisException( "Salt not found for user. Is this user registered?" );
        }

        try {
            return CredentialFactory.deriveCredential( password, encryptedSalt );
        } catch ( SecurityConfigurationException | InvalidKeySpecException | NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        }
    }

    private KeyPair loadRsaKeys(
            PasswordCryptoService crypto,
            UUID userKey,
            DataStore dataStore,
            DirectoryApi keyClient ) throws IrisException {
        KeyPair keyPair = null;

        try {
            logger.debug( "Loading RSA keys from disk" );
            keyPair = new LocalRsaKeyLoader( crypto, keyClient, dataStore ).load();
        } catch ( KodexException e ) {
            logger.debug( "Could not load RSA keys from disk, trying network... {}", e.getMessage() );
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
                logger.debug( "Could not load RSA keys from network, trying to generate... {}", e.getMessage() );
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

    @Override
    public String getUserCredential() {
        return userCredential;
    }

    @Override
    public UUID getUserId() {
        return userKey;
    }

    @Override
    public String getUrl() {
        return url;
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

    @Override
    public CryptoServiceLoader getCryptoServiceLoader() {
        return loader;
    }

    @Override
    public KryptnosticEngine getKryptnosticEngine() {
        return engine;
    }

    @Override
    public CryptoKeyStorageApi getCryptoKeyStorageApi() {
        return cryptoKeyStorageApi;
    }

    @Override
    public RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException {
        return new RsaCompressingCryptoService( RsaKeyLoader.CIPHER, getRsaPrivateKey(), getRsaPublicKey() );
    }

    private KryptnosticEngine loadEngine() throws IrisException {
        /*
         * First let's make sure we can encrypt/decrypt.
         */
        CryptoService privateKeyCryptoService;
        try {
            privateKeyCryptoService = loader.get( KryptnosticEngine.PRIVATE_KEY ).get();
        } catch ( Exception e1 ) {
            // This should only happen when the server return bad data. Fail.
            throw new Error( "Unable to get or generate AES keys." );
        }

        KryptnosticEngine engine = new KryptnosticEngine();
        ObjectMapper mapper = KodexObjectMapperFactory.getSmileMapper();
        byte[] privateKey = null;
        byte[] searchPrivateKey = null;
        try {
            /*
             * First we try loading keys from data store.
             */
            Optional<byte[]> maybePrivateKeyBytes = Optional.fromNullable( dataStore
                    .get( KryptnosticEngine.PRIVATE_KEY ) );
            Optional<byte[]> maybeSearchPrivateKeyBytes = Optional.fromNullable( dataStore
                    .get( KryptnosticEngine.SEARCH_PRIVATE_KEY ) );
            if ( maybePrivateKeyBytes.isPresent() && maybeSearchPrivateKeyBytes.isPresent() ) {
                privateKey = privateKeyCryptoService.decryptBytes( mapper.readValue( maybePrivateKeyBytes.get(),
                        BlockCiphertext.class ) );
                searchPrivateKey = privateKeyCryptoService.decryptBytes( mapper.readValue( maybeSearchPrivateKeyBytes
                        .get(),
                        BlockCiphertext.class ) );
                engine.initClient( privateKey, searchPrivateKey );
            } else {
                // If some keys are absent locally let's try and pull from the network.
                throw new IOException( "Unable to load kryptnostic engine keys." );
            }
        } catch ( SecurityConfigurationException | IOException e ) {
            try {
                Optional<BlockCiphertext> encryptedPrivateKey = cryptoKeyStorageApi.getFHEPrivateKeyForCurrentUser();
                Optional<BlockCiphertext> encryptedSearchPrivateKey = cryptoKeyStorageApi
                        .getFHESearchPrivateKeyForUser();
                if ( encryptedPrivateKey.isPresent() && encryptedSearchPrivateKey.isPresent() ) {
                    privateKey = privateKeyCryptoService.decryptBytes( encryptedPrivateKey.get() );
                    searchPrivateKey = privateKeyCryptoService.decryptBytes( encryptedSearchPrivateKey.get() );
                } else { 
                    throw new SecurityConfigurationException( "Unable to load FHE keys from server.");
                }
            } catch ( BadRequestException | SecurityConfigurationException e1 ) {
                // If have a problem retrieving data from the server or decrypting keys, we regenerate.
                engine.initClient();
                privateKey = Preconditions.checkNotNull( engine.getPrivateKey(),
                        "Private key from engine cannot be null." );
                searchPrivateKey = Preconditions.checkNotNull( engine.getSearchPrivateKey(),
                        "Search private key cannot be null." );
                try {
                    cryptoKeyStorageApi.setHashFunctionForCurrentUser( engine.getClientHashFunction() );
                } catch ( BadRequestException e2 ) {
                    throw new IrisException( e2 );
                }
            }

            try {
                // Let's store the keys locally
                BlockCiphertext encryptedPrivateKey = privateKeyCryptoService.encrypt( privateKey );
                BlockCiphertext encryptedSearchPrivateKey = privateKeyCryptoService.encrypt( searchPrivateKey );
                dataStore.put( KryptnosticEngine.PRIVATE_KEY, mapper.writeValueAsBytes( encryptedPrivateKey )
                        );
                dataStore.put( KryptnosticEngine.SEARCH_PRIVATE_KEY,
                        mapper.writeValueAsBytes( encryptedSearchPrivateKey ) );
                
                cryptoKeyStorageApi.setFHEPrivateKeyForCurrentUser( encryptedPrivateKey );
                cryptoKeyStorageApi.setFHESearchPrivateKeyForCurrentUser( encryptedSearchPrivateKey );
                
            } catch ( IOException | SecurityConfigurationException | BadRequestException e1 ) {
                logger.error( "Unable to configure FHE keys." );
                throw new Error( "Sad times.Freeze? I'm a robot. I'm not a refrigerator. " );
            }
        }

        return engine;
    }
}
