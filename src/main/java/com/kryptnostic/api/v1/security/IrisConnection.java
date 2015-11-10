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
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.rsa.FreshRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.LocalRsaKeyLoader;
import com.kryptnostic.api.v1.security.loaders.rsa.NetworkRsaKeyLoader;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.authentication.CredentialFactory;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.crypto.ciphers.BlockCiphertext;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.search.v1.http.SearchApi;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.crypto.KryptnosticCryptoServiceLoader;
import com.kryptnostic.v2.sharing.api.SharingApi;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;
import com.kryptnostic.v2.storage.models.keys.BootstrapKeyIds;
import com.kryptnostic.v2.storage.uuids.ReservedObjectUUIDs;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger                   logger  = LoggerFactory
                                                                  .getLogger( IrisConnection.class );
    private transient final PasswordCryptoService cryptoService;
    private final UUID                            userKey;
    private final String                          userCredential;
    private final String                          url;
    private final DirectoryApi                    keyService;
    private final ObjectStorageApi                objectStorageApi;
    private final KeyStorageApi                   keyStorageApi;
    private final SearchApi                       searchApi;
    private final SharingApi                      sharingApi;
    private final MetadataStorageApi              metadataStorageApi;
    private final DataStore                       dataStore;
    private final PublicKey                       rsaPublicKey;
    private final PrivateKey                      rsaPrivateKey;
    private final CryptoServiceLoader             loader;
    boolean                                       doFresh = false;
    private final KryptnosticEngine               engine;
    private final byte[]                          clientHashFunction;

    // TODO: Make constructor that can take mock services.
    // public IrisConnection( String url, UUID userKey, String password, DataStore dataStore, Client client ,
    // DirectoryApi directoryApi , ObjectStorageApi objectStorageApi , KeyStorageApi keyStorageApi, SearchApi searchApi,
    // MetadataStorageApi storageApi ) {
    // this.url = url;
    // this.userKey = userKey;
    // this.
    // }

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
        this.keyStorageApi = adapter.create( KeyStorageApi.class );
        this.objectStorageApi = adapter.create( ObjectStorageApi.class );
        this.metadataStorageApi = adapter.create( MetadataStorageApi.class );
        this.searchApi = adapter.create( SearchApi.class );
        this.sharingApi = adapter.create( SharingApi.class );

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

        this.loader = new KryptnosticCryptoServiceLoader( this, keyStorageApi, objectStorageApi, Cypher.AES_CTR_128 );
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
        BootstrapKeyIds bootstrapKeyIds = keyStorageApi.getBootstrapInformation();

        KryptnosticEngineHolder holder = new KryptnosticEngineHolder();
        /*
         * First let's make sure we can encrypt/decrypt.
         */
        CryptoService privateKeyCryptoService;
        try {
            privateKeyCryptoService = loader.getLatest( ReservedObjectUUIDs.PRIVATE_KEY ).get();
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
                    .get( ReservedObjectUUIDs.PRIVATE_KEY.toString() ) );
            Optional<byte[]> maybeSearchPrivateKeyBytes = Optional.fromNullable( dataStore
                    .get( ReservedObjectUUIDs.SEARCH_PRIVATE_KEY.toString() ) );
            Optional<byte[]> maybeClientHashFunction = Optional.fromNullable( dataStore
                    .get( ReservedObjectUUIDs.CLIENT_HASH_FUNCTION.toString() ) );
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
                    throw new SecurityConfigurationException( "Unable to load FHE keys from server." );
                }
            } catch ( SecurityConfigurationException e1 ) {
                // If have a problem retrieving data from the server or decrypting keys, we regenerate.
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
                dataStore.put( ReservedObjectUUIDs.PRIVATE_KEY.toString(),
                        mapper.writeValueAsBytes( encryptedPrivateKey )
                        );
                dataStore.put( ReservedObjectUUIDs.SEARCH_PRIVATE_KEY.toString(),
                        mapper.writeValueAsBytes( encryptedSearchPrivateKey ) );
                dataStore.put( ReservedObjectUUIDs.CLIENT_HASH_FUNCTION.toString(),
                        mapper.writeValueAsBytes( holder.clientHashFunction ) );

            } catch ( IOException e1 ) {
                logger.error( "Unable to configure FHE keys." );
                throw new Error( "Sad times.Freeze? I'm a robot. I'm not a refrigerator. " );
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
    public SearchApi getSearchApi() {
        return searchApi;
    }

    @Override
    public SharingApi getSharingApi() {
        return sharingApi;
    }

    @Override
    public DirectoryApi getDirectoryApi() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public KeyStorageApi getKeyStorageApi() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public KryptnosticClient getClient() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public KryptnosticCryptoManager getCryptoManager() {
        // TODO Auto-generated method stub
        return null;
    }
}
