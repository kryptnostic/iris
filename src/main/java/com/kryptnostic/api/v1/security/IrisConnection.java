package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Optional;
import com.google.common.base.Preconditions;
import com.google.common.base.Stopwatch;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.client.DefaultKryptnosticClient;
import com.kryptnostic.api.v1.client.DefaultKryptnosticCryptoManager;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.rsa.FreshRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.LocalRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.NetworkRsaKeyLoader;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.authentication.CredentialFactory;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.v2.constants.Names;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.crypto.KryptnosticCryptoServiceLoader;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.sharing.api.SharingApi;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.api.ObjectListingApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;

import retrofit.RestAdapter;
import retrofit.client.Client;

public class IrisConnection implements KryptnosticConnection {

    private static final Logger                       logger     = LoggerFactory
                                                                         .getLogger( IrisConnection.class );
    protected static final DeflatingJacksonMarshaller marshaller = new DeflatingJacksonMarshaller();
    private transient final PasswordCryptoService     cryptoService;
    private final UUID                                userKey;
    private final String                              userCredential;
    private final String                              url;
    private final DirectoryApi                        directoryApi;
    private final ObjectStorageApi                    objectStorageApi;
    private final ObjectListingApi                    objectListingApi;
    private final KeyStorageApi                       keyStorageApi;
    private final SearchApi                           searchApi;
    private final SharingApi                          sharingApi;
    private final MetadataStorageApi                  metadataStorageApi;
    private final DataStore                           dataStore;
    private final PublicKey                           rsaPublicKey;
    private final PrivateKey                          rsaPrivateKey;
    private final CryptoServiceLoader                 loader;
    boolean                                           doFresh    = false;
    private final KryptnosticEngine                   engine;
    private final byte[]                              clientHashFunction;
    private final CryptoService                       masterCryptoService;

    public IrisConnection( String url, UUID userKey, String password, DataStore dataStore, Client client )
            throws IrisException {
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

        RestAdapter v1Adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter(
                url.replace( "/v2", "/v1" ),
                userKey,
                credential,
                client );
        this.directoryApi = v1Adapter.create( DirectoryApi.class );
        this.metadataStorageApi = v1Adapter.create( MetadataStorageApi.class );

        RestAdapter v2Adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter(
                url,
                userKey,
                credential,
                client );
        this.keyStorageApi = v2Adapter.create( KeyStorageApi.class );
        this.objectStorageApi = v2Adapter.create( ObjectStorageApi.class );
        this.objectListingApi = v2Adapter.create( ObjectListingApi.class );
        this.searchApi = v2Adapter.create( SearchApi.class );
        this.sharingApi = v2Adapter.create( SharingApi.class );

        this.userCredential = credential;
        this.userKey = userKey;
        this.url = url;
        this.dataStore = dataStore;

        /**
         * Load basic RSA keys into connection or generate them
         */
        Stopwatch watch = Stopwatch.createStarted();
        if ( keyPair == null ) {
            keyPair = loadRsaKeys( cryptoService, userKey, dataStore, directoryApi );
        }
        this.rsaPrivateKey = keyPair.getPrivate();
        this.rsaPublicKey = keyPair.getPublic();
        logger.trace( "[PROFILE] load rsa keys {} ms", watch.elapsed( TimeUnit.MILLISECONDS ) );

        this.loader = new KryptnosticCryptoServiceLoader( this, keyStorageApi, objectStorageApi, Cypher.AES_CTR_128 );
        masterCryptoService = loadMasterCryptoService();
        KryptnosticEngineHolder holder = loadEngine();
        this.engine = holder.engine;
        this.clientHashFunction = holder.clientHashFunction;
    }

    private static String bootstrapCredential( UUID userKey, String url, String password, Client client )
            throws IrisException {
        RestAdapter bootstrap = KryptnosticRestAdapter.createWithNoAuthAndDefaultJacksonConverter( url, client );
        BlockCiphertext encryptedSalt = bootstrap.create( KeyStorageApi.class ).getEncryptedSalt( userKey );
        if ( encryptedSalt == null ) {
            throw new IrisException( "Salt not found for user. Is this user registered?" );
        }

        try {
            return CredentialFactory.deriveCredential( password, encryptedSalt );
        } catch ( SecurityConfigurationException | InvalidKeySpecException | NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        }
    }

    private CryptoService loadMasterCryptoService() throws IrisException {
        byte[] cryptoServiceBytes = null;
        try {
            cryptoServiceBytes = dataStore.get( MASTER_CRYPTO_SERVICE );
        } catch ( IOException e ) {
            logger.warn( "Unable to load crypto service bytes from disk." );
        }

        if ( cryptoServiceBytes == null ) {
            logger.info( "Trying to load master crypto service from network " );
            cryptoServiceBytes = keyStorageApi.getMasterCryptoService();
        }

        try {
            if ( cryptoServiceBytes == null ) {
                CryptoService cs = new AesCryptoService( Cypher.AES_CTR_128 );
                byte[] encryptedMasterKey = newCryptoManager().getRsaCryptoService().encrypt( cs );
                dataStore.put( MASTER_CRYPTO_SERVICE, encryptedMasterKey );
                return cs;
            } else {
                return newCryptoManager().getRsaCryptoService().decrypt( keyStorageApi.getMasterCryptoService(),
                        AesCryptoService.class );
            }
        } catch (
                SecurityConfigurationException
                | IOException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException e ) {
            logger.error( "Something went wrong while loading master key. ", e );
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
                keyPair = new NetworkRsaKeyLoader( crypto, keyStorageApi, userKey ).load();
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
        keyStorageApi.setRSAPrivateKey( encPrivKey );
        logger.debug( "Done flushing RSA privkey to web." );

        logger.debug( "Flushing RSA pubkey to web..." );
        keyStorageApi.setRSAPublicKey( pubKey );
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
    public DataStore getLocalDataStore() {
        return dataStore;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return rsaPrivateKey;
    }

    @Override
    public PublicKey getPublicKey() {
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
    public KeyStorageApi getCryptoKeyStorageApi() {
        return keyStorageApi;
    }

    private static class KryptnosticEngineHolder {
        public KryptnosticEngine engine;
        public byte[]            clientHashFunction;
    }

    private KryptnosticEngineHolder loadEngine() throws IrisException {
        KryptnosticEngineHolder holder = new KryptnosticEngineHolder();
        /*
         * First let's make sure we can encrypt/decrypt.
         */
        CryptoService privateKeyCryptoService;
        try {
            privateKeyCryptoService = cryptoService;
        } catch ( Exception e1 ) {
            // This should only happen when the server return bad data. Fail.
            throw new Error( "Unable to get or generate AES keys." );
        }

        KryptnosticEngine engine = new KryptnosticEngine();
        holder.engine = engine;

        ObjectMapper mapper = KodexObjectMapperFactory.getSmileMapper();
        byte[] privateKey = null;
        byte[] searchPrivateKey = null;
        BlockCiphertext encryptedPrivateKey;
        BlockCiphertext encryptedSearchPrivateKey;

        try {
            /*
             * First we try loading keys from data store.
             */
            Optional<byte[]> maybePrivateKeyBytes = Optional.fromNullable( dataStore
                    .get( Names.FHE_PRIVATE_KEY ) );
            Optional<byte[]> maybeSearchPrivateKeyBytes = Optional.fromNullable( dataStore
                    .get( Names.FHE_SEARCH_PRIVATE_KEY ) );
            Optional<byte[]> maybeClientHashFunction = Optional.fromNullable( dataStore
                    .get( Names.CLIENT_HASH_FUNCTION ) );
            boolean privateKeyPresent = maybePrivateKeyBytes.isPresent();
            boolean searchPrivateKeyPresent = maybeSearchPrivateKeyBytes.isPresent();
            boolean clientHashPresent = maybeClientHashFunction.isPresent();
            if ( !privateKeyPresent || !searchPrivateKeyPresent || !clientHashPresent ) {
                // If some keys are absent locally let's try and pull from the network.
                throw new IOException( "Unable to load kryptnostic engine keys." );
            }
            privateKey = privateKeyCryptoService.decryptBytes( mapper.readValue( maybePrivateKeyBytes.get(),
                    BlockCiphertext.class ) );
            searchPrivateKey = privateKeyCryptoService.decryptBytes( mapper.readValue( maybeSearchPrivateKeyBytes
                    .get(),
                    BlockCiphertext.class ) );
            engine.initClient( privateKey, searchPrivateKey );
            holder.clientHashFunction = maybeClientHashFunction.get();
            return holder;
        } catch ( SecurityConfigurationException | IOException e ) {
            try {
                Optional<BlockCiphertext> maybeEncryptedPrivateKey = keyStorageApi
                        .getFHEPrivateKeyForCurrentUser();
                Optional<BlockCiphertext> maybeEncryptedSearchPrivateKey = keyStorageApi
                        .getFHESearchPrivateKeyForUser();
                byte[] maybeClientHashFunction = keyStorageApi.getHashFunctionForCurrentUser();
                // TODO: Check that the length matches the expected length for the client hash function.
                if ( maybeEncryptedPrivateKey.isPresent() && maybeEncryptedSearchPrivateKey.isPresent()
                        && ( maybeClientHashFunction.length > 0 ) ) {
                    encryptedPrivateKey = maybeEncryptedPrivateKey.get();
                    encryptedSearchPrivateKey = maybeEncryptedSearchPrivateKey.get();
                    privateKey = privateKeyCryptoService.decryptBytes( encryptedPrivateKey );
                    searchPrivateKey = privateKeyCryptoService.decryptBytes( encryptedSearchPrivateKey );

                    engine.initClient( privateKey, searchPrivateKey );
                    holder.clientHashFunction = maybeClientHashFunction;
                } else {
                    throw new SecurityConfigurationException( "Unable to load FHE keys from server.", e );
                }
            } catch ( SecurityConfigurationException e1 ) {
                // If have a problem retrieving data from the serve or decrypting keys, we regenerate.
                engine.initClient();
                privateKey = Preconditions.checkNotNull( engine.getPrivateKey(),
                        "Private key from engine cannot be null." );
                searchPrivateKey = Preconditions.checkNotNull( engine.getSearchPrivateKey(),
                        "Search private key cannot be null." );
                holder.clientHashFunction = engine.getClientHashFunction();
                /*
                 * Need to flush to network since we just generated.
                 */
                try {
                    encryptedPrivateKey = privateKeyCryptoService.encrypt( privateKey );
                    encryptedSearchPrivateKey = privateKeyCryptoService.encrypt( searchPrivateKey );
                    keyStorageApi.setHashFunctionForCurrentUser( holder.clientHashFunction );
                    keyStorageApi.setFHEPrivateKeyForCurrentUser( encryptedPrivateKey );
                    keyStorageApi.setFHESearchPrivateKeyForCurrentUser( encryptedSearchPrivateKey );
                } catch ( SecurityConfigurationException e2 ) {
                    throw new IrisException( e2 );
                }
            }

            /*
             * If we got here then keys came from network or were freshly created and need to be flushed to disk.
             */
            try {
                dataStore.put( Names.FHE_PRIVATE_KEY,
                        mapper.writeValueAsBytes( encryptedPrivateKey ) );
                dataStore.put( Names.FHE_SEARCH_PRIVATE_KEY,
                        mapper.writeValueAsBytes( encryptedSearchPrivateKey ) );
                dataStore.put( Names.CLIENT_HASH_FUNCTION,
                        mapper.writeValueAsBytes( holder.clientHashFunction ) );

            } catch ( IOException e1 ) {
                logger.error( "Unable to configure FHE keys.", e1 );
                throw new Error( "Sad times.Freeze? I'm a robot. I'm not a refrigerator. ", e1 );
            }

        }

        return holder;
    }

    @Override
    public byte[] getClientHashFunction() {
        return clientHashFunction;
    }

    @Override
    public MetadataStorageApi getMetadataApi() {
        return metadataStorageApi;
    }

    @Override
    public ObjectStorageApi getObjectStorageApi() {
        return objectStorageApi;
    }

    @Override
    public ObjectListingApi getObjectListingApi() {
        return objectListingApi;
    }

    @Override
    public SearchApi getSearchApi() {
        return searchApi;
    }

    @Override
    public SharingApi getSharingApi() {
        return sharingApi;
    }

    @Override
    public DirectoryApi getDirectoryApi() {
        return directoryApi;
    }

    @Override
    public KeyStorageApi getKeyStorageApi() {
        return keyStorageApi;
    }

    @Override
    public KryptnosticClient newClient() throws ClassNotFoundException, IrisException, ResourceNotFoundException,
            IOException, ExecutionException, SecurityConfigurationException {
        return new DefaultKryptnosticClient( this );
    }

    @Override
    public KryptnosticCryptoManager newCryptoManager() {
        // TODO: Why is this a factory method?
        return new DefaultKryptnosticCryptoManager( this );
    }

    @Override
    public CryptoService getMasterCryptoService() {
        return masterCryptoService;
    }
}
