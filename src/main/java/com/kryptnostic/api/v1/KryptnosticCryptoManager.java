package com.kryptnostic.api.v1;

import java.util.Map;
import java.util.Set;
import java.util.UUID;

import com.kryptnostic.indexing.v1.ObjectSearchPair;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingCryptoService;
import com.kryptnostic.kodex.v1.crypto.ciphers.RsaCompressingEncryptionService;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.v2.storage.models.VersionedObjectKey;

/**
 * KryptnosticContext is responsible for maintaining shared state between the KryptnosticClient and Kryptnostic
 * services.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 */
public interface KryptnosticCryptoManager {

    byte[] rsaDecrypt( byte[] ciphertext ) throws SecurityConfigurationException;

    byte[] rsaEncrypt( byte[] plaintext ) throws SecurityConfigurationException;

    void registerObjectSearchPair( VersionedObjectKey objectKey, ObjectSearchPair indexPair );

    void registerObjectSearchPairs( Map<VersionedObjectKey, ObjectSearchPair> indexPairs );

    byte[] prepareSearchToken( String token );

    Map<UUID, RsaCompressingEncryptionService> getEncryptionServiceForUsers( Set<UUID> users );

    RsaCompressingCryptoService getRsaCryptoService() throws SecurityConfigurationException;

    byte[] generateIndexForToken( String token, byte[] objectIndexPair );

}
