package com.kryptnostic.api.v1.security.loaders.fhe;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.kryptnostic.api.v1.client.InMemoryStore;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.kodex.v1.crypto.keys.Keys;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.CorruptKodexException;
import com.kryptnostic.kodex.v1.crypto.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.multivariate.util.SimplePolynomialFunctions;
import com.kryptnostic.storage.v1.http.SearchFunctionStorageApi;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

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
        SearchFunctionStorageApi searchFunctionService = Mockito.mock( SearchFunctionStorageApi.class );
        Mockito.when( searchFunctionService.setQueryHasherPair( Mockito.any( QueryHasherPairRequest.class ) ) )
                .thenReturn( new BasicResponse<String>( "", 200, true ) );

        Kodex<String> kodex = new FreshKodexLoader(
                keyPair,
                globalHashFunction,
                searchFunctionService,
                new InMemoryStore() ).load();
        Assert.assertFalse( kodex.isSealed() );
        Assert.assertTrue( kodex.isDirty() );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( com.kryptnostic.crypto.PublicKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( EncryptedSearchPrivateKey.class ) );
        Assert.assertNotNull( kodex.getKeyWithJackson( QueryHasherPairRequest.class.getCanonicalName(), String.class ) );
    }

    @Test(
        expected = NullPointerException.class )
    public void nullTest() throws KodexException {
        new FreshKodexLoader( keyPair, null, Mockito.mock( SearchFunctionStorageApi.class ), new InMemoryStore() ).load();
    }

}
