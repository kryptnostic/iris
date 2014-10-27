package com.kryptnostic.api.v1.security.loaders;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import org.apache.commons.lang3.tuple.Pair;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.base.Preconditions;
import com.kryptnostic.api.v1.security.KodexLoader;
import com.kryptnostic.crypto.EncryptedSearchPrivateKey;
import com.kryptnostic.crypto.v1.ciphers.BlockCiphertext;
import com.kryptnostic.crypto.v1.ciphers.CryptoService;
import com.kryptnostic.crypto.v1.ciphers.Cypher;
import com.kryptnostic.crypto.v1.keys.Keys;
import com.kryptnostic.crypto.v1.keys.Kodex;
import com.kryptnostic.crypto.v1.keys.Kodex.CorruptKodexException;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.directory.v1.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.exceptions.types.KodexException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.linear.EnhancedBitMatrix.SingularMatrixException;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;
import com.kryptnostic.storage.v1.models.request.QueryHasherPairRequest;

public class FreshKodexLoader extends KodexLoader {

    private final CryptoService            crypto;
    private final SimplePolynomialFunction globalHashFunction;

    public FreshKodexLoader( CryptoService crypto, SimplePolynomialFunction globalHashFunction ) {
        Preconditions.checkNotNull( globalHashFunction );
        Preconditions.checkNotNull( crypto );
        this.crypto = crypto;
        this.globalHashFunction = globalHashFunction;
    }

    /**
     * Attempt to generate a brand new Kodex
     * 
     * @throws KodexException
     */
    @Override
    public Kodex<String> tryLoadingKodex() throws KodexException {
        KeyPair pair;
        try {
            pair = Keys.generateRsaKeyPair( 1024 );
            BlockCiphertext privateKeyCiphertext = crypto.encrypt( pair.getPrivate().getEncoded() );
            byte[] publicKey = pair.getPublic().getEncoded();

            Kodex<String> kodex = new Kodex<String>(
                    Cypher.RSA_OAEP_SHA1_1024,
                    Cypher.AES_CTR_PKCS5_128,
                    pair.getPublic() );

            kodex.verify( pair.getPublic() );
            kodex.unseal( pair.getPrivate() );

            kodex.setKeyWithJackson( PrivateKey.class.getCanonicalName(), privateKeyCiphertext, BlockCiphertext.class );
            kodex.setKeyWithJackson(
                    PublicKey.class.getCanonicalName(),
                    new PublicKeyEnvelope( publicKey ),
                    PublicKeyEnvelope.class );

            com.kryptnostic.crypto.PrivateKey fhePrivateKey = getFhePrivateKey();
            com.kryptnostic.crypto.PublicKey fhePublicKey = getFhePublicKey( fhePrivateKey );

            kodex.setKeyWithClassAndJackson( com.kryptnostic.crypto.PrivateKey.class, fhePrivateKey );
            kodex.setKeyWithClassAndJackson( com.kryptnostic.crypto.PublicKey.class, fhePublicKey );

            EncryptedSearchPrivateKey encryptedSearchPrivateKey = getEncryptedSearchPrivateKey();
            QueryHasherPairRequest queryHasher = getQueryHasher( encryptedSearchPrivateKey, fhePrivateKey );

            kodex.setKeyWithClassAndJackson( EncryptedSearchPrivateKey.class, encryptedSearchPrivateKey );
            kodex.setKeyWithJackson(
                    SimplePolynomialFunction.class.getCanonicalName() + KodexLoader.LEFT_HASHER,
                    queryHasher.getLeft(),
                    SimplePolynomialFunction.class );
            kodex.setKeyWithJackson(
                    SimplePolynomialFunction.class.getCanonicalName() + KodexLoader.LEFT_HASHER,
                    queryHasher.getRight(),
                    SimplePolynomialFunction.class );

            return kodex;
        } catch (
                SingularMatrixException
                | SealedKodexException
                | InvalidKeyException
                | SignatureException
                | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException
                | JsonProcessingException
                | SecurityConfigurationException
                | CorruptKodexException e ) {
            throw new KodexException( e );
        }
    }

    private QueryHasherPairRequest getQueryHasher(
            EncryptedSearchPrivateKey encryptedSearchPrivateKey,
            com.kryptnostic.crypto.PrivateKey fhePrivateKey ) throws SingularMatrixException {
        Pair<SimplePolynomialFunction, SimplePolynomialFunction> pair = encryptedSearchPrivateKey.getQueryHasherPair(
                globalHashFunction,
                fhePrivateKey );
        return new QueryHasherPairRequest( pair.getLeft(), pair.getRight() );
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
