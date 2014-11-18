package com.kryptnostic.api.v1.security.loaders.fhe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.PrivateKey;
import com.kryptnostic.crypto.PublicKey;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class LocalKodexLoaderTests {
    private static final Logger      logger = LoggerFactory.getLogger( LocalKodexLoaderTests.class );
    private CryptoService            cryptoService;
    private DataStore                dataStore;
    private ObjectMapper             mapper = KodexObjectMapperFactory.getObjectMapper();

    private PrivateKey               fhePrivateKey;
    private PublicKey                fhePublicKey;
    private SimplePolynomialFunction globalHash;

    @Before
    public void init() throws NoSuchAlgorithmException, IOException, SecurityConfigurationException {

        String password = "test";
        dataStore = Mockito.mock( DataStore.class );
        cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, password.toCharArray() );

        fhePrivateKey = new PrivateKey( 128, 64 );
        fhePublicKey = new PublicKey( fhePrivateKey );

        globalHash = SimplePolynomialFunctions.denseRandomMultivariateQuadratic( 128, 64 );
    }

    @Test
    public void initTest() throws IrisException, KodexException, SecurityConfigurationException,
            NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidAlgorithmParameterException,
            SignatureException, SealedKodexException, CorruptKodexException, SingularMatrixException,
            InvalidKeySpecException {
        KeyPair pair = makeValidRsa();
        makeValidKodex( pair );

        Kodex<String> kodex = new LocalKodexLoader( pair, dataStore ).load();

        Assert.assertFalse( kodex.isSealed() );
        Assert.assertFalse( kodex.isDirty() );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( QueryHasherPairRequest.class.getCanonicalName(), String.class ) );
    }

    private KeyPair makeValidRsa() throws NoSuchAlgorithmException, IOException, SecurityConfigurationException,
            InvalidKeySpecException {
        KeyPair pair = Keys.generateRsaKeyPair( 1024 );
        Assert.assertEquals( pair.getPublic(), Keys.publicKeyFromPrivateKey( pair.getPrivate() ) );

        Mockito.when( dataStore.get( java.security.PrivateKey.class.getCanonicalName().getBytes() ) ).thenReturn(
                mapper.writeValueAsBytes( cryptoService.encrypt( pair.getPrivate().getEncoded() ) ) );
        Mockito.when( dataStore.get( java.security.PublicKey.class.getCanonicalName().getBytes() ) ).thenReturn(
                pair.getPublic().getEncoded() );

        return pair;
    }

    private void makeValidKodex( KeyPair pair ) throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, SecurityConfigurationException, IOException,
            SealedKodexException, KodexException, CorruptKodexException, SingularMatrixException {
        Kodex<String> kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_PKCS5_128, pair.getPublic() );

        kodex.unseal( pair.getPublic(), pair.getPrivate() );

        kodex.setKeyWithClassAndJackson( PrivateKey.class, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( PublicKey.class, fhePublicKey );

        EncryptedSearchPrivateKey esp = new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHash.getOutputLength() ) );
        Pair<SimplePolynomialFunction, SimplePolynomialFunction> p = esp.getQueryHasherPair( globalHash, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( EncryptedSearchPrivateKey.class, esp );
        kodex.setKeyWithJackson(
                QueryHasherPairRequest.class.getCanonicalName(),
                new QueryHasherPairRequest( p.getLeft(), p.getRight() ).computeChecksum(),
                String.class );

        byte[] kodexBytes = mapper.writeValueAsBytes( kodex );

        Kodex<String> actual = mapper.readValue( kodexBytes, new TypeReference<Kodex<String>>() {} );

        actual.verify( pair.getPublic() );

        Mockito.when( dataStore.get( Kodex.class.getCanonicalName().getBytes() ) ).thenReturn( kodexBytes );
    }
}
