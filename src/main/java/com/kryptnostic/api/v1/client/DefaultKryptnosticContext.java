package com.kryptnostic.api.v1.client;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cyphers;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

/**
 *
 * The default kryptnostic context is instantiated from an
 *
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultKryptnosticContext implements KryptnosticCryptoManager {
    private final SharingApi            sharingApi;
    private final KeyStorageApi         keyStorageApi;
    private final KryptnosticConnection connection;

    private static final Logger         logger = LoggerFactory
                                                       .getLogger( DefaultKryptnosticContext.class );

    public DefaultKryptnosticContext(
            KryptnosticConnection connection ) throws IrisException {
        this.sharingApi = connection.getSharingApi();
        this.keyStorageApi = connection.getKeyStorageApi();
        this.connection = connection;
    }

    @Override
    public void registerObjectSearchPair( VersionedObjectKey objectId, ObjectSearchPair indexPair ) {
        sharingApi.addSearchPairs( ImmutableMap.of( objectId, indexPair ) );
    }

    @Override
    public void registerObjectSearchPairs( Map<VersionedObjectKey, ObjectSearchPair> indexPairs ) {
        sharingApi.addSearchPairs( indexPairs );
    }

    @Override
    public byte[] generateIndexForToken( String token, byte[] objectIndexPair ) {
        byte[] searchHash = getHashedToken( token );
        byte[] indexForTerm = connection.getKryptnosticEngine().clientGetMetadatumAddress( objectIndexPair,
                searchHash );
        return indexForTerm;
    }

    public static byte[] getHashedToken( String token ) {
        return foldByteArray( Hashing.sha256().hashBytes( token.getBytes( Charsets.UTF_16 ) ).asBytes() );
    }

    public static byte[] foldByteArray( byte[] input ) {
        Preconditions.checkState( ( input.length & 1 ) == 0, "Length of input must be divisible by 2." );
        byte[] folded = new byte[ input.length >>> 1 ];
        for ( int i = 0; i < folded.length; ++i ) {
            folded[ i ] = (byte) ( input[ i ] ^ input[ i + folded.length ] );
        }
        if ( folded.length != 16 ) {
            logger.warn( "Unexpected hash lenght: {}", folded.length );
        }
        return folded;
    }

    @Override
    public byte[] prepareSearchToken( String token ) {
        return connection.getKryptnosticEngine().getEncryptedSearchToken( getHashedToken( token ) );
    }

    @Override
    public byte[] rsaDecrypt( byte[] ciphertext ) throws SecurityConfigurationException {
        return Cyphers.decrypt( RsaKeyLoader.CIPHER, connection.getPrivateKey(), ciphertext );
    }

    @Override
    public byte[] rsaEncrypt( byte[] plaintext ) throws SecurityConfigurationException {
        return Cyphers.encrypt( RsaKeyLoader.CIPHER, connection.getPublicKey(), plaintext );
    }

    @Override
    public Map<UUID, RsaCompressingEncryptionService> getEncryptionServiceForUsers( Set<UUID> users ) {
        return Maps.asMap( users, new Function<UUID, RsaCompressingEncryptionService>() {

            @Override
            public RsaCompressingEncryptionService apply( UUID input ) {
                try {
                    return new RsaCompressingEncryptionService( RsaKeyLoader.CIPHER, new PublicKeyEnvelope(
                            keyStorageApi.getPublicKey(
                                    input ) ).asRsaPublicKey() );
                } catch (
                        InvalidKeySpecException
                        | NoSuchAlgorithmException
                        | SecurityConfigurationException e ) {
                    return null;
                }
            }
        } );
    }

    @Override
    public RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException {
        return new RsaCompressingCryptoService(
                RsaKeyLoader.CIPHER,
                connection.getPrivateKey(),
                connection.getPublicKey() );
    }
}
