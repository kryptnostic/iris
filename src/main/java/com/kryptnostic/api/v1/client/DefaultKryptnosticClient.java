package com.kryptnostic.api.v1.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.api.v1.search.DefaultSearchClient;
import com.kryptnostic.api.v1.sharing.SharingManager;
import com.kryptnostic.api.v1.storage.DefaultStorageClient;
import com.kryptnostic.directory.v1.DirectoryClient;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.storage.v1.StorageClient;

public class DefaultKryptnosticClient implements KryptnosticClient {
    private static DeflatingJacksonMarshaller marshaller = new DeflatingJacksonMarshaller();
    private ObjectMapper                      mapper;

    private final KryptnosticContext          context;

    private final SearchClient                searchClient;
    private final StorageClient               storageClient;
    private final SharingClient               sharingClient;
    private final DirectoryClient             directoryClient;

    public DefaultKryptnosticClient( KryptnosticServicesFactory factory, KryptnosticConnection connection ) throws IrisException,
            ResourceNotFoundException {
        mapper = KodexObjectMapperFactory.getObjectMapper( connection.getCryptoServiceLoader() );
        this.context = new DefaultKryptnosticContext(
                factory.createSearchFunctionApi(),
                factory.createSharingApi(),
                factory.createDirectoryApi(),
                connection );

        this.storageClient = new DefaultStorageClient(
                context,
                factory.createDocumentApi(),
                factory.createMetadataApi(),
                factory.createSharingApi() );
        this.searchClient = new DefaultSearchClient( context, factory.createSearchApi() );
        this.directoryClient = new DefaultDirectoryClient( context, factory.createDirectoryApi() );
        this.sharingClient = new SharingManager( context, factory.createSharingApi() );
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
