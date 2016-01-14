package com.kryptnostic.api.v1;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.crypto.ciphers.CryptoService;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.storage.DataStore;
import com.kryptnostic.krypto.engine.KryptnosticEngine;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.v2.crypto.CryptoServiceLoader;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.sharing.api.SharingApi;
import com.kryptnostic.v2.storage.api.KeyStorageApi;
import com.kryptnostic.v2.storage.api.ObjectListingApi;
import com.kryptnostic.v2.storage.api.ObjectStorageApi;
import com.kryptnostic.v2.storage.api.TypesApi;

/**
 * Manages connection state for making API requests against the Kryptnostic API. *
 *
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public interface KryptnosticConnection {
    //TODO: Move this somewhere else.
    String MASTER_CRYPTO_SERVICE = "master-crypto-service";
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
    
    CryptoService getMasterCryptoService();

    KryptnosticEngine getKryptnosticEngine();

    byte[] getClientHashFunction();

    String getUrl();

    CryptoServiceLoader getCryptoServiceLoader();

    KeyStorageApi getCryptoKeyStorageApi();

    MetadataStorageApi getMetadataApi();

    ObjectStorageApi getObjectStorageApi();

    ObjectListingApi getObjectListingApi();

    SearchApi getSearchApi();

    SharingApi getSharingApi();

    DirectoryApi getDirectoryApi();

    KeyStorageApi getKeyStorageApi();
    
    TypesApi getTypesApi();

    DataStore getLocalDataStore();

    /**
     * Retrieves the higher level client API.
     *
     * @return An instance of {@link KryptnosticClient}
     * @throws ResourceNotFoundException
     * @throws IrisException
     * @throws ClassNotFoundException
     * @throws SecurityConfigurationException 
     * @throws ExecutionException 
     * @throws IOException 
     */
    KryptnosticClient newClient() throws ClassNotFoundException, IrisException, ResourceNotFoundException, IOException, ExecutionException, SecurityConfigurationException;

    KryptnosticCryptoManager newCryptoManager();

}
