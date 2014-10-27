package com.kryptnostic.api.v1.security.loaders;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.kryptnostic.api.v1.security.KodexLoader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.users.v1.UserKey;

public class NetworkKodexLoaderTests {
    private KeyApi        keyClient;
    private UserKey       userKey;
    private CryptoService cryptoService;

    // TODO: finish this test!

    @Before
    public void init() {
        cryptoService = new CryptoService( Cypher.AES_CTR_PKCS5_128, "test".toCharArray() );
        userKey = new UserKey( "krypt", "sina" );
        keyClient = Mockito.mock( KeyApi.class );
    }

    @Test
    // THIS SHOULD BE FAILING NOW
    public void initTest() throws IrisException, KodexException, SecurityConfigurationException, SealedKodexException,
            CorruptKodexException {
        Kodex<String> kodex = new NetworkKodexLoader( keyClient, userKey, cryptoService ).loadKodex();
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

}
