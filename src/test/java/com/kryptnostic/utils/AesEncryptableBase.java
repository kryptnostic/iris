package com.kryptnostic.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.JacksonKodexMarshaller;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

/**
 * Provides some utilities for setting up AES encryption
 * 
 * @author sinaiman
 *
 */
public class AesEncryptableBase extends BaseSerializationTest {
    protected CryptoService crypto;
    protected KeyPair       pair;
    protected Kodex<String> kodex;

    protected void initImplicitEncryption() throws NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidParameterSpecException, SealedKodexException, IOException,
            SignatureException, CorruptKodexException, KodexException, SecurityConfigurationException {
        resetSecurityConfiguration();
        // register key with object mapper
        this.kodex.unseal( pair.getPrivate() );
        this.kodex.setKey( CryptoService.class.getCanonicalName(), new JacksonKodexMarshaller<CryptoService>(
                CryptoService.class ), crypto );
    }

    protected void initFheEncryption() throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException,
            SealedKodexException, IOException, SignatureException, CorruptKodexException, KodexException,
            SecurityConfigurationException {
        PrivateKey privateKey = new PrivateKey( 128, 64 );
        PublicKey publicKey = new PublicKey( privateKey );

        kodex.unseal( pair.getPrivate() );
        kodex.setKey( PrivateKey.class.getCanonicalName(), new JacksonKodexMarshaller<PrivateKey>(
                PrivateKey.class,
                mapper ), privateKey );
        kodex.setKey( PublicKey.class.getCanonicalName(), new JacksonKodexMarshaller<PublicKey>(
                PublicKey.class,
                mapper ), publicKey );
    }

    protected void resetSecurityConfiguration() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException,
            InvalidKeySpecException, InvalidParameterSpecException, SealedKodexException, IOException,
            SignatureException, CorruptKodexException, SecurityConfigurationException, KodexException {
        this.pair = Keys.generateRsaKeyPair( 1024 );
        this.kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_PKCS5_128, pair.getPublic() );
        this.kodex.unseal( pair.getPrivate() );
        this.mapper = KodexObjectMapperFactory.getObjectMapper( kodex );
        this.crypto = new CryptoService( Cypher.AES_CTR_PKCS5_128, new BigInteger( 130, new SecureRandom() ).toString(
                32 ).toCharArray() );

    }
}
