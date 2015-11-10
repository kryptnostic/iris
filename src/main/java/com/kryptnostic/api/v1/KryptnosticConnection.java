package com.kryptnostic.api.v1;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.sharing.api.SharingApi;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;

/**
 * Manages connection state for making API requests against the Kryptnostic API. *
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public interface KryptnosticConnection {
    /**
     * Retrieves the security principal for this connection.
     * 
     * @return The UUID of the security principal for this connection.
     */
    UUID getUserId();

    /**
     * Retrieves the authenticator for this connection.
     * 
     * @return A string representation of the authenticator for this connection.
     */
    // TODO: Is this base64 or Hex?
    String getUserCredential();

    PrivateKey getPrivateKey();

    PublicKey getPublicKey();

    KryptnosticEngine getKryptnosticEngine();

    byte[] getClientHashFunction();

    String getUrl();

    CryptoServiceLoader getCryptoServiceLoader();

    KeyStorageApi getCryptoKeyStorageApi();

    MetadataStorageApi getMetadataApi();

    ObjectStorageApi getObjectStorageApi();

    SearchApi getSearchApi();

    SharingApi getSharingApi();

    DirectoryApi getDirectoryApi();

    KeyStorageApi getKeyStorageApi();

    DataStore getLocalDataStore();

    /**
     * Retrieves the higher level client API.
     * 
     * @return An instance of {@link KryptnosticClient}
     * @throws ResourceNotFoundException 
     * @throws IrisException 
     * @throws ClassNotFoundException 
     */
    KryptnosticClient newClient() throws ClassNotFoundException, IrisException, ResourceNotFoundException;
    
    KryptnosticCryptoManager newCryptoManager();

}
