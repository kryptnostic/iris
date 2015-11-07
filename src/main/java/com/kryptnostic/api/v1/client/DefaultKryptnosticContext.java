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
import com.kryptnostic.api.v1.security.loaders.rsa.RsaKeyLoader;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.crypto.ciphers.Cyphers;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v2.models.VersionedObjectKey;

/**
 *
 * The default kryptnostic context is instantiated from an
 *
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultKryptnosticContext implements KryptnosticContext {
    private final SharingApi            sharingClient;
    private final DirectoryApi          directoryClient;
    private final KryptnosticConnection connection;

    public static final String          CHECKSUM_KEY = "global.hash.checksum";
    public static final String          FUNCTION_KEY = "global.hash.function";

    private static final Logger         logger       = LoggerFactory
                                                             .getLogger( DefaultKryptnosticContext.class );

    public DefaultKryptnosticContext(
            SharingApi sharingClient,
            DirectoryApi directoryClient,
            KryptnosticConnection connection ) throws IrisException {
        this.sharingClient = sharingClient;
        this.directoryClient = directoryClient;
        this.connection = connection;
    }

    @Override
    public KryptnosticConnection getConnection() {
        return this.connection;
    }

    @Override
    public void addIndexPair( VersionedObjectKey objectId, ObjectSearchPair indexPair ) {
        sharingClient.addSearchPairs( ImmutableMap.of( objectId, indexPair ) );
    }

    @Override
    public void addIndexPairs( Map<VersionedObjectKey, ObjectSearchPair> indexPairs ) {
        sharingClient.addSearchPairs( indexPairs );
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
        return Cyphers.decrypt( RsaKeyLoader.CIPHER, connection.getRsaPrivateKey(), ciphertext );
    }

    @Override
    public byte[] rsaEncrypt( byte[] plaintext ) throws SecurityConfigurationException {
        return Cyphers.encrypt( RsaKeyLoader.CIPHER, connection.getRsaPublicKey(), plaintext );
    }

    @Override
    public Map<UUID, RsaCompressingEncryptionService> getEncryptionServiceForUsers( Set<UUID> users ) {
        return Maps.asMap( users, new Function<UUID, RsaCompressingEncryptionService>() {

            @Override
            public RsaCompressingEncryptionService apply( UUID input ) {
                try {
                    return new RsaCompressingEncryptionService( RsaKeyLoader.CIPHER, directoryClient.getPublicKey(
                            input ).asRsaPublicKey() );
                } catch (
                        InvalidKeySpecException
                        | NoSuchAlgorithmException
                        | SecurityConfigurationException
                        | ResourceNotFoundException e ) {
                    return null;
                }
            }
        } );
    }

    @Override
    public RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException {
        return connection.getRsaCryptoService();
    }
}
