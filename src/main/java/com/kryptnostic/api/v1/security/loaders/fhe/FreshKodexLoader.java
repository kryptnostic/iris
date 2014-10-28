package com.kryptnostic.api.v1.security.loaders.fhe;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import org.apache.commons.lang3.tuple.Pair;

import com.google.common.base.Preconditions;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.utils.SimplePolynomialFunctionValidator;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class FreshKodexLoader extends KodexLoader {

    private final KeyPair                  keyPair;
    private final SimplePolynomialFunction globalHashFunction;
    private final DataStore                dataStore;

    public FreshKodexLoader( KeyPair keyPair, SimplePolynomialFunction globalHashFunction, DataStore dataStore ) {
        Preconditions.checkNotNull( globalHashFunction );
        Preconditions.checkNotNull( keyPair );
        this.keyPair = keyPair;
        this.globalHashFunction = globalHashFunction;
        this.dataStore = dataStore;
    }

    /**
     * Attempt to generate a brand new Kodex
     * 
     * @throws KodexException
     */
    @Override
    public Kodex<String> tryLoading() throws KodexException {
        try {
            Kodex<String> kodex = new Kodex<String>(
                    Cypher.RSA_OAEP_SHA1_1024,
                    Cypher.AES_CTR_PKCS5_128,
                    keyPair.getPublic() );

            kodex.verify( keyPair.getPublic() );
            kodex.unseal( keyPair.getPrivate() );

            generateAllKeys( kodex );

            return kodex;
        } catch (
                SingularMatrixException
                | SealedKodexException
                | InvalidKeyException
                | SignatureException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | SecurityConfigurationException
                | CorruptKodexException
                | IOException e ) {
            throw new KodexException( e );
        }
    }

    private void generateAllKeys( Kodex<String> kodex ) throws SealedKodexException, KodexException,
            SecurityConfigurationException, SingularMatrixException, IOException {
        com.kryptnostic.crypto.PrivateKey fhePrivateKey = getFhePrivateKey();
        com.kryptnostic.crypto.PublicKey fhePublicKey = getFhePublicKey( fhePrivateKey );

        kodex.setKeyWithClassAndJackson( com.kryptnostic.crypto.PrivateKey.class, fhePrivateKey );
        kodex.setKeyWithClassAndJackson( com.kryptnostic.crypto.PublicKey.class, fhePublicKey );

        EncryptedSearchPrivateKey encryptedSearchPrivateKey = getEncryptedSearchPrivateKey();
        QueryHasherPairRequest queryHasher = getQueryHasher( encryptedSearchPrivateKey, fhePrivateKey );

        kodex.setKeyWithClassAndJackson( EncryptedSearchPrivateKey.class, encryptedSearchPrivateKey );
        kodex.setKeyWithClassAndJackson( QueryHasherPairRequest.class, queryHasher );

        // queryHasher.getLeft(),
        // SimplePolynomialFunction.class );
        // kodex.setKeyWithJackson(
        // SimplePolynomialFunction.class.getCanonicalName() + KodexLoader.LEFT_HASHER,
        // queryHasher.getRight(),
        // SimplePolynomialFunction.class );

    }

    private QueryHasherPairRequest getQueryHasher(
            EncryptedSearchPrivateKey encryptedSearchPrivateKey,
            com.kryptnostic.crypto.PrivateKey fhePrivateKey ) throws SingularMatrixException, IOException {
        Pair<SimplePolynomialFunction, SimplePolynomialFunction> pair = encryptedSearchPrivateKey.getQueryHasherPair(
                globalHashFunction,
                fhePrivateKey );
        SimplePolynomialFunctionValidator leftValidtor = new SimplePolynomialFunctionValidator( pair.getLeft(), 10000 );
        SimplePolynomialFunctionValidator rightValidtor = new SimplePolynomialFunctionValidator( pair.getRight(), 10000 );

        dataStore.put( KodexLoader.LEFT_VALIDATOR, leftValidtor.getBytes() );
        dataStore.put( KodexLoader.RIGHT_VALIDATOR, rightValidtor.getBytes() );
        
        return new QueryHasherPairRequest( pair.getLeft(), pair.getRight() );

        // SimplePolynomialFunction expected = pair.getLeft();
        // SimplePolynomialFunction actual = requestPair.getLeft();
        //
        // Preconditions.checkState( expected.equals( actual ) , "Kodex just got fucked on the left." );
        // expected = pair.getRight();
        // actual = requestPair.getRight();
        // Preconditions.checkState( expected.equals( actual ) , "Kodex just got fucked on the right." );
        // return requestPair;
    }

    private EncryptedSearchPrivateKey getEncryptedSearchPrivateKey() throws SingularMatrixException {
        return new EncryptedSearchPrivateKey( (int) Math.sqrt( globalHashFunction.getOutputLength() ) );
    }

    private com.kryptnostic.crypto.PublicKey getFhePublicKey( com.kryptnostic.crypto.PrivateKey fhePrivateKey ) {
        return new com.kryptnostic.crypto.PublicKey( fhePrivateKey );
    }

    private com.kryptnostic.crypto.PrivateKey getFhePrivateKey() {
        return new com.kryptnostic.crypto.PrivateKey( 128, 64 );
    }
}
