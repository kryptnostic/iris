package com.kryptnostic.api.v1.security.loaders.fhe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.users.v1.UserKey;

public class NetworkKodexLoaderTests {
    private KeyApi                   keyClient;
    private UserKey                  userKey;
    private CryptoService            cryptoService;
    private KeyPair                  keyPair;
    private PrivateKey               fhePrivateKey;
    private PublicKey                fhePublicKey;
    private SimplePolynomialFunction globalHash;
    private ObjectMapper             mapper = KodexObjectMapperFactory.getObjectMapper();

    @Before
    public void init() throws NoSuchAlgorithmException {
        cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, "test".toCharArray() );
        userKey = new UserKey( "krypt", "sina" );
        keyClient = Mockito.mock( KeyApi.class );

        keyPair = Keys.generateRsaKeyPair( 1024 );

        fhePrivateKey = new PrivateKey( 128, 64 );
        fhePublicKey = new PublicKey( fhePrivateKey );

        globalHash = SimplePolynomialFunctions.denseRandomMultivariateQuadratic( 128, 64 );
    }

    @Test
    public void initTest() throws IrisException, KodexException, SecurityConfigurationException, SealedKodexException,
            CorruptKodexException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, IOException, SingularMatrixException {

        Mockito.when( keyClient.getKodex() ).thenReturn( makeValidKodex() );

        Kodex<String> kodex = new NetworkKodexLoader( keyPair, keyClient ).load();
        Assert.assertFalse( kodex.isSealed() );
        Assert.assertFalse( kodex.isDirty() );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                + KodexLoader.LEFT_HASHER, SimplePolynomialFunction.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                + KodexLoader.RIGHT_HASHER, SimplePolynomialFunction.class ) );
    }

    private Kodex<String> makeValidKodex() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, SecurityConfigurationException, IOException,
            SealedKodexException, KodexException, CorruptKodexException, SingularMatrixException {
        Kodex<String> kodex = new Kodex<String>(
                Cypher.RSA_OAEP_SHA1_1024,
                Cypher.AES_CTR_PKCS5_128,
                keyPair.getPublic() );

        kodex.unseal( keyPair.getPrivate() );

        kodex.setKeyWithClassAndJackson( PrivateKey.class, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( PublicKey.class, fhePublicKey );

        EncryptedSearchPrivateKey esp = new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHash.getOutputLength() ) );
        Pair<SimplePolynomialFunction, SimplePolynomialFunction> p = esp.getQueryHasherPair( globalHash, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( EncryptedSearchPrivateKey.class, esp );
        kodex.setKeyWithJackson(
                SimplePolynomialFunction.class.getCanonicalName() + KodexLoader.LEFT_HASHER,
                p.getLeft(),
                SimplePolynomialFunction.class );
        kodex.setKeyWithJackson(
                SimplePolynomialFunction.class.getCanonicalName() + KodexLoader.RIGHT_HASHER,
                p.getRight(),
                SimplePolynomialFunction.class );

        kodex.seal();

        return kodex;
    }
}
