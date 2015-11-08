package com.kryptnostic.api.v1.client;

import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.search.DefaultSearchClient;
import com.kryptnostic.api.v1.sharing.SharingManager;
import com.kryptnostic.api.v1.storage.DefaultStorageClient;
import com.kryptnostic.api.v1.storage.StorageClient;
import com.kryptnostic.directory.v1.DirectoryClient;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.sharing.v1.SharingClient;

public class DefaultKryptnosticClient implements KryptnosticClient {
    private final KryptnosticContext context;

    private final SearchClient       searchClient;
    private final StorageClient      storageClient;
    private final SharingClient      sharingClient;
    private final DirectoryClient    directoryClient;

    public DefaultKryptnosticClient( KryptnosticConnection connection ) throws IrisException,
            ResourceNotFoundException {
        this( new DefaultKryptnosticContext(
                connection.getSharingApi(),
                connection.getDirectoryApi(),
                connection ), new DefaultStorageClient(
                context,
                connection.getDocumentApi(),
                connection.getMetadataApi(),
                connection.getSharingApi() ),
                new DefaultSearchClient( context, factory.createSearchApi() ),
                new DefaultDirectoryClient( context, factory.createDirectoryApi() ), new SharingManager(
                        context,
                        factory.createSharingApi(),
                        connection.getKryptnosticEngine() ) );
    }

    public DefaultKryptnosticClient(
            KryptnosticContext context,
            SearchClient searchClient,
            StorageClient storageClient,
            SharingClient sharingClient,
            DirectoryClient directoryClient ) {
        this.context = context;
        this.searchClient = searchClient;
        this.storageClient = storageClient;
        this.sharingClient = sharingClient;
        this.directoryClient = directoryClient;
    }

    @Override
    public KryptnosticContext getContext() {
        return this.context;
    }

    @Override
    public SharingClient getSharingClient() {
        return sharingClient;
    }

    @Override
    public KryptnosticConnection getConnection() {
        return this.context.getConnection();
    }

    @Override
    public DirectoryClient getDirectoryClient() {
        return this.directoryClient;
    }

    @Override
    public SearchClient getSearchClient() {
        return this.searchClient;
    }

    @Override
    public StorageClient getStorageClient() {
        return this.storageClient;
    }

}
