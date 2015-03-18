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
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.principal.UserKey;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cypher;
import com.kryptnostic.kodex.v1.crypto.ciphers.PasswordCryptoService;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class NetworkKodexLoaderTests {
    private DirectoryApi             keyClient;
    private UserKey                  userKey;
    private PasswordCryptoService    cryptoService;
    private KeyPair                  keyPair;
    private PrivateKey               fhePrivateKey;
    private PublicKey                fhePublicKey;
    private SimplePolynomialFunction globalHash;
    private ObjectMapper             mapper = KodexObjectMapperFactory.getObjectMapper();

    @Before
    public void init() throws NoSuchAlgorithmException {
        cryptoService = new PasswordCryptoService( Cypher.AES_CTR_128, "test".toCharArray() );
        userKey = new UserKey( "krypt", "sina" );
        keyClient = Mockito.mock( DirectoryApi.class );

        keyPair = Keys.generateRsaKeyPair( 1024 );

        fhePrivateKey = new PrivateKey( 128, 64 );
        fhePublicKey = new PublicKey( fhePrivateKey );

        globalHash = SimplePolynomialFunctions.denseRandomMultivariateQuadratic( 128, 64 );
    }

    @Test
    public void initTest() throws IrisException, KodexException, SecurityConfigurationException, SealedKodexException,
            CorruptKodexException, InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            SignatureException, IOException, SingularMatrixException, ResourceNotFoundException {

        Mockito.when( keyClient.getKodex() ).thenReturn( makeValidKodex() );

        Kodex<String> kodex = new NetworkKodexLoader( keyPair, keyClient ).load();
        Assert.assertFalse( kodex.isSealed() );
        Assert.assertFalse( kodex.isDirty() );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( QueryHasherPairRequest.class.getCanonicalName(), String.class ) );
    }

    private Kodex<String> makeValidKodex() throws InvalidKeyException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, SignatureException, SecurityConfigurationException, IOException,
            SealedKodexException, KodexException, CorruptKodexException, SingularMatrixException {
        Kodex<String> kodex = new Kodex<String>( Cypher.RSA_OAEP_SHA1_1024, Cypher.AES_CTR_128, keyPair.getPublic() );

        kodex.unseal( keyPair.getPublic(), keyPair.getPrivate() );

        kodex.setKeyWithClassAndJackson( PrivateKey.class, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( PublicKey.class, fhePublicKey );

        EncryptedSearchPrivateKey esp = new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHash.getOutputLength() ) );
        Pair<SimplePolynomialFunction, SimplePolynomialFunction> p = esp.getQueryHasherPair( globalHash, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( EncryptedSearchPrivateKey.class, esp );
        kodex.setKeyWithJackson(
                QueryHasherPairRequest.class.getCanonicalName(),
                new QueryHasherPairRequest( p.getLeft(), p.getRight() ).computeChecksum(),
                String.class );

        kodex.seal();

        return kodex;
    }
}
