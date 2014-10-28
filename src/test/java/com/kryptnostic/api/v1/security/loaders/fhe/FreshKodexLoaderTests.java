package com.kryptnostic.api.v1.security.loaders.fhe;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.kryptnostic.api.v1.client.InMemoryStore;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;

public class FreshKodexLoaderTests {

    private KeyPair                  keyPair;
    private SimplePolynomialFunction globalHashFunction;

    @Before
    public void init() throws NoSuchAlgorithmException {
        globalHashFunction = SimplePolynomialFunctions.denseRandomMultivariateQuadratic( 128, 64 );
        keyPair = Keys.generateRsaKeyPair( 1024 );
    }

    @Test
    public void initTest() throws IrisException, KodexException, SecurityConfigurationException, SealedKodexException,
            CorruptKodexException {
        Kodex<String> kodex = new FreshKodexLoader( keyPair, globalHashFunction , new InMemoryStore() ).load();
        Assert.assertFalse( kodex.isSealed() );
        Assert.assertTrue( kodex.isDirty() );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                + KodexLoader.LEFT_HASHER, SimplePolynomialFunction.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( SimplePolynomialFunction.class.getCanonicalName()
                + KodexLoader.RIGHT_HASHER, SimplePolynomialFunction.class ) );
    }

    @Test(
        expected = NullPointerException.class )
    public void nullTest() throws KodexException {
        new FreshKodexLoader( keyPair, null , new InMemoryStore() ).load();
    }

}
