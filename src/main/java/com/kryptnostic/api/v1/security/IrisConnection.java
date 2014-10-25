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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.api.v1.client.KryptnosticRestAdapter;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.PublicKeyAlgorithm;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.directory.v1.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.users.v1.UserKey;

public class IrisConnection implements KryptnosticConnection {
    private final Kodex<String>     kodex;
    private transient CryptoService cryptoService;
    private final UserKey           userKey;
    private final String            userCredential;
    private final String            url;
    private final KeyApi            keyService;
    private final DataStore         dataStore;

    public IrisConnection(
            Kodex<String> kodex,
            CryptoService cryptoService,
            UserKey userKey,
            String userCredential,
            String url ) {
        this.kodex = kodex;
        this.cryptoService = cryptoService;
        this.userKey = userKey;
        this.userCredential = userCredential;
        this.url = url;
        this.keyService = null;
        this.dataStore = null;
    }

    public IrisConnection( String url, UserKey userKey, String userCredential, DataStore dataStore ) throws IrisException {
        Kodex<String> k = null;
        this.cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, userCredential.toCharArray() );
        keyService = KryptnosticRestAdapter.createWithDefaultJacksonConverter( url, userKey, userCredential ).create(
                KeyApi.class );

        this.userCredential = userCredential;
        this.userKey = userKey;
        this.url = url;

        try {
            PrivateKey privateKey = loadOrCreatePrivateKey( keyService, dataStore, cryptoService );
            PublicKey publicKey = loadOrCreatePublicKey( keyService, dataStore, cryptoService, userKey );
            k = loadOrCreateKodex( keyService, dataStore, cryptoService, publicKey, privateKey );
            k.unseal( privateKey );
        } catch ( Exception e ) {
            wrapException( e );
        }
        this.kodex = k;
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
        } catch ( InvalidKeyException e ) {
            throw new IrisException( e );
        } catch ( InvalidKeySpecException e ) {
            throw new IrisException( e );
        } catch ( NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        } catch ( InvalidAlgorithmParameterException e ) {
            throw new IrisException( e );
        } catch ( NoSuchPaddingException e ) {
            throw new IrisException( e );
        } catch ( IllegalBlockSizeException e ) {
            throw new IrisException( e );
        } catch ( BadPaddingException e ) {
            throw new IrisException( e );
        }
    }

    @Override
    public BlockCiphertext encryptPrivateKey( PrivateKey privateKey ) throws IrisException {
        try {
            return cryptoService.encrypt( privateKey.getEncoded() );
        } catch ( InvalidKeyException e ) {
            throw new IrisException( e );
        } catch ( InvalidKeySpecException e ) {
            throw new IrisException( e );
        } catch ( NoSuchAlgorithmException e ) {
            throw new IrisException( e );
        } catch ( NoSuchPaddingException e ) {
            throw new IrisException( e );
        } catch ( IllegalBlockSizeException e ) {
            throw new IrisException( e );
        } catch ( BadPaddingException e ) {
            throw new IrisException( e );
        } catch ( InvalidParameterSpecException e ) {
            throw new IrisException( e );
        }
    }

    public void flushKodex() throws IOException {
        ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
        if ( keyService != null ) {
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
            byte[] privateKeyCiphertext = dataStore.get( PrivateKey.class.getCanonicalName().getBytes() );
            if ( privateKeyCiphertext != null ) {
                encryptedPrivateKey = mapper.readValue( privateKeyCiphertext, BlockCiphertext.class );
            } else {
                encryptedPrivateKey = keyService.getPrivateKey();
                if ( encryptedPrivateKey == null ) {
                    KeyPair pair = Keys.generateRsaKeyPair( 1024 );
                    encryptedPrivateKey = crypto.encrypt( pair.getPrivate().getEncoded() );
                    keyService.setPrivateKey( encryptedPrivateKey );
                    keyService.setPublicKey( new PublicKeyEnvelope( pair.getPublic().getEncoded() ) );
                    dataStore.put( PublicKey.class.getCanonicalName().getBytes(), pair.getPublic().getEncoded() );
                }
                // Always write the private key to local storage
                dataStore.put(
                        PrivateKey.class.getCanonicalName().getBytes(),
                        mapper.writeValueAsBytes( encryptedPrivateKey ) );
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
            ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
            PublicKeyEnvelope envelope;
            byte[] publicKeyBytes = dataStore.get( PublicKey.class.getCanonicalName().getBytes() );
            if ( publicKeyBytes == null ) {
                envelope = keyService.getPublicKey( userKey.getRealm(), userKey.getName() );
                dataStore.put( PublicKey.class.getCanonicalName().getBytes(), envelope.getBytes() );
            }
            return Keys.publicKeyFromBytes( PublicKeyAlgorithm.RSA, publicKeyBytes );
        } catch ( Exception e ) {
            wrapException( e );
            return null;
        }
    }

    public static Kodex<String> loadOrCreateKodex(
            KeyApi keyService,
            DataStore dataStore,
            CryptoService crypto,
            PublicKey publicKey,
            PrivateKey privateKey ) throws IrisException {
        Kodex<String> kodex;
        try {
            ObjectMapper mapper = KodexObjectMapperFactory.getObjectMapper();
            byte[] kodexBytes = dataStore.get( Kodex.class.getCanonicalName().getBytes() );

            if ( kodexBytes != null ) {
                kodex = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );
            } else {
                kodex = keyService.getKodex();
                if ( kodex == null ) {
                    kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_PKCS5_128, publicKey );
                    kodex.unseal( privateKey );
                    com.kryptnostic.crypto.PrivateKey fhePrv = new com.kryptnostic.crypto.PrivateKey( 128, 64 );
                    com.kryptnostic.crypto.PublicKey fhePub = new com.kryptnostic.crypto.PublicKey( fhePrv );
                    kodex.setKey(
                            com.kryptnostic.crypto.PrivateKey.class.getCanonicalName(),
                            new JacksonKodexMarshaller<com.kryptnostic.crypto.PrivateKey>(
                                    com.kryptnostic.crypto.PrivateKey.class ),
                            fhePrv );
                    kodex.setKey(
                            com.kryptnostic.crypto.PublicKey.class.getCanonicalName(),
                            new JacksonKodexMarshaller<com.kryptnostic.crypto.PublicKey>(
                                    com.kryptnostic.crypto.PublicKey.class ),
                            fhePub );
                    kodex.setKey( CryptoService.class.getCanonicalName(), new JacksonKodexMarshaller<CryptoService>(
                            CryptoService.class ), crypto );
                    keyService.setKodex( kodex );
                }
                dataStore.put( Kodex.class.getCanonicalName().getBytes(), mapper.writeValueAsBytes( kodex ) );
            }
            return kodex;
        } catch ( Exception e ) {
            wrapException( e );
            return null;
        }
    }

    public static <T> void store( KeyApi keyService, DataStore dataStore, T encryptedSearchPrivateKey, Class<T> clazz ) {

    }

    public static void store(
            KeyApi keyService,
            DataStore dataStore,
            EncryptedSearchPrivateKey encryptedSearchPrivateKey ) {

    }

    public static void wrapException( Exception e ) throws IrisException {
        throw new IrisException( e );
    }

}
