package com.kryptnostic.api.v1.security;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;
import com.kryptnostic.users.v1.UserKey;

public class IrisConnection implements KryptnosticConnection {
    private static final Logger                     logger  = LoggerFactory.getLogger( IrisConnection.class );
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
    boolean                                         doFresh = false;

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
        this.dataStore = null;
        try {

            // loadRsaKeys( cryptoService, userKey, dataStore, keyService );
            this.rsaPublicKey = keyPair.getPublic();

            kodex.unseal( keyPair.getPrivate() );

            this.fhePrivateKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            this.fhePublicKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            this.encryptedSearchPrivateKey = kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
        } catch ( KodexException | SecurityConfigurationException | CorruptKodexException e ) {
            throw new IrisException( e );
        }
    }

    public IrisConnection( String url, UserKey userKey, String userCredential, DataStore dataStore ) throws IrisException {
        this.cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, userCredential.toCharArray() );
        RestAdapter adapter = KryptnosticRestAdapter.createWithDefaultJacksonConverter( url, userKey, userCredential );
        this.keyService = adapter.create( KeyApi.class );
        SearchFunctionApi searchFunctionService = adapter.create( SearchFunctionApi.class );
        SimplePolynomialFunction globalHashFunction;
        try {
            globalHashFunction = searchFunctionService.getFunction();
        } catch ( ResourceNotFoundException e ) {
            throw new IrisException( e );
        }

        this.userCredential = userCredential;
        this.userKey = userKey;
        this.url = url;
        this.dataStore = dataStore;

        KeyPair keyPair = loadRsaKeys( cryptoService, userKey, dataStore, keyService );

        this.rsaPublicKey = keyPair.getPublic();

        Kodex<String> searchKodex = loadSearchKodex( dataStore, keyPair, keyService, globalHashFunction );

        // TODO: insert document keyring/kodex here!
        this.kodex = searchKodex;

        try {
            this.fhePrivateKey = searchKodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            this.fhePublicKey = searchKodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            this.encryptedSearchPrivateKey = searchKodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
        } catch ( KodexException | SecurityConfigurationException e ) {
            throw new IrisException( e );
        }

        try {
            this.kodex.setKeyWithClassAndJackson( CryptoService.class, cryptoService );
        } catch ( SealedKodexException e1 ) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch ( KodexException e1 ) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch ( SecurityConfigurationException e1 ) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        if ( doFresh ) {
            try {
                BlockCiphertext encPrivKey = cryptoService.encrypt( keyPair.getPrivate().getEncoded() );
                byte[] pubKey = keyPair.getPublic().getEncoded();
                ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();

                // Flush to disk
                dataStore.put( PrivateKey.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( encPrivKey ) );
                dataStore.put( PublicKey.class.getCanonicalName().getBytes(), pubKey );
                dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( searchKodex ) );

                // Flush to service.
                keyService.setPrivateKey( encPrivKey );
                keyService.setPublicKey( new PublicKeyEnvelope( pubKey ) );
                keyService.setKodex( searchKodex );
                try {
                    searchFunctionService.setQueryHasherPair( new QueryHasherPairRequest( searchKodex
                            .getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                                    + KodexLoader.LEFT_HASHER, SimplePolynomialFunction.class ), searchKodex
                            .getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                                    + KodexLoader.RIGHT_HASHER, SimplePolynomialFunction.class ) ) );
                } catch ( SealedKodexException | SecurityConfigurationException | KodexException e ) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            } catch ( SecurityConfigurationException | IOException e ) {
                throw new IrisException( e );
            }

        }
    }

    private KeyPair loadRsaKeys( CryptoService crypto, UserKey userKey, DataStore dataStore, KeyApi keyClient )
            throws IrisException {
        KeyPair keyPair = null;

        try {
            keyPair = new LocalRsaKeyLoader( crypto, dataStore ).load();
        } catch ( KodexException e ) {
            logger.info( "Could not load RSA keys from disk, trying network... {}", e );
        }
        if ( keyPair == null ) {
            try {
                keyPair = new NetworkRsaKeyLoader( crypto, keyClient, userKey ).load();
            } catch ( KodexException e ) {
                logger.info( "Could not load RSA keys from network, trying to generate... {}", e );
            }
        }
        if ( keyPair == null ) {
            try {
                doFresh = true;
                keyPair = new FreshRsaKeyLoader().load();
            } catch ( KodexException e ) {
                logger.info( "Could not generate RSA Keys! {}", e );
            }
        }
        if ( keyPair == null ) {
            throw new IrisException( "Could not load RSA Keys" );
        }
        return keyPair;
    }

    private Kodex<String> loadSearchKodex(
            DataStore dataStore,
            KeyPair keyPair,
            KeyApi keyService,
            SimplePolynomialFunction globalHashFunction ) throws IrisException {

        Kodex<String> searchKodex = null;
        try {
            searchKodex = new LocalKodexLoader( keyPair, dataStore ).load();
        } catch ( KodexException e ) {
            logger.info( "Could not load Kodex from disk, trying network... {}", e );
        }
        if ( searchKodex == null ) {
            try {
                searchKodex = new NetworkKodexLoader( keyPair, keyService ).load();
            } catch ( KodexException e ) {
                logger.info( "Could not load Kodex from network, trying to generate... {}", e );
            }
        }
        if ( searchKodex == null && ( doFresh == true ) ) {
            try {
                doFresh = true;
                searchKodex = new FreshKodexLoader( keyPair, globalHashFunction ).load();
            } catch ( KodexException e ) {
                logger.info( "Could not generate Kodex! {}", e );
            }
        }
        if ( searchKodex == null ) {
            throw new IrisException( "Could not load Kodex" );
        }
        return searchKodex;
    }

    @Override
    public String getUserCredential() {
        return userCredential;
    }

    @Override
    public UserKey getUserKey() {
        return userKey;
    }

    // private void flushKodex() throws IOException {
    // ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
    // if ( dataStore != null ) {
    // dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( kodex ) );
    // }
    // if ( keyService != null ) {
    // keyService.setKodex( kodex );
    // }
    // }

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

}
