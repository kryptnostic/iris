package com.kryptnostic.api.v1.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.api.v1.security.loaders.FreshKodexLoader;
import com.kryptnostic.api.v1.security.loaders.LocalKodexLoader;
import com.kryptnostic.api.v1.security.loaders.NetworkKodexLoader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;
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
    private final PublicKey                         rsaPublicKey;
    private final EncryptedSearchPrivateKey         encryptedSearchPrivateKey;

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
            this.fhePrivateKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            this.fhePublicKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            this.encryptedSearchPrivateKey = kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
            this.rsaPublicKey = kodex.getKeyWithJackson( PublicKey.class );
        } catch ( KodexException | SecurityConfigurationException e ) {
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

        this.kodex = loadSearchKodex( dataStore, cryptoService, userKey, keyService, globalHashFunction );

        try {
            this.fhePrivateKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class );
            this.fhePublicKey = kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class );
            this.rsaPublicKey = kodex.getKeyWithJackson( PublicKey.class );
            this.encryptedSearchPrivateKey = kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class );
        } catch ( KodexException | SecurityConfigurationException e ) {
            throw new IrisException( e );
        }
    }

    private Kodex<String> loadSearchKodex(
            DataStore dataStore,
            CryptoService cryptoService,
            UserKey userKey,
            KeyApi keyService,
            SimplePolynomialFunction globalHashFunction ) throws IrisException {
        Kodex<String> searchKodex = null;
        try {
            searchKodex = new LocalKodexLoader( dataStore, cryptoService ).loadKodex();
        } catch ( KodexException e ) {
            logger.info( "Could not load Kodex from disk, trying network... {}", e );
        }
        if ( searchKodex == null ) {
            try {
                searchKodex = new NetworkKodexLoader( keyService, userKey, cryptoService ).loadKodex();
            } catch ( KodexException e ) {
                logger.info( "Could not load Kodex from network, trying to generate... {}", e );
            }
        }
        if ( searchKodex == null ) {
            try {
                searchKodex = new FreshKodexLoader( cryptoService, globalHashFunction ).loadKodex();
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
