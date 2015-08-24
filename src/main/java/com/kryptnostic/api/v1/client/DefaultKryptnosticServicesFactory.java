package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;

import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.search.v1.http.SearchApi;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.http.MetadataStorageApi;
import com.kryptnostic.storage.v1.http.ObjectStorageApi;
import com.kryptnostic.storage.v1.http.SearchFunctionStorageApi;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger     logger = LoggerFactory.getLogger( DefaultKryptnosticServicesFactory.class );

    private final MetadataStorageApi              metadataApi;
    private final ObjectStorageApi                documentApi;
    private final SearchApi                searchApi;
    private final SearchFunctionStorageApi searchFunctionApi;
    private final SharingApi               sharingApi;
    private final DirectoryApi             directoryApi;

    public DefaultKryptnosticServicesFactory( KryptnosticConnection credentialService ) {
        this( KryptnosticRestAdapter.create( credentialService ) );
    }

    public DefaultKryptnosticServicesFactory( RestAdapter restAdapter ) {
        documentApi = restAdapter.create( ObjectStorageApi.class );
        metadataApi = restAdapter.create( MetadataStorageApi.class );
        searchApi = restAdapter.create( SearchApi.class );
        searchFunctionApi = restAdapter.create( SearchFunctionStorageApi.class );
        sharingApi = restAdapter.create( SharingApi.class );
        directoryApi = restAdapter.create( DirectoryApi.class );
    }

    @Override
    public MetadataStorageApi createMetadataApi() {
        return metadataApi;
    }

    @Override
    public ObjectStorageApi createDocumentApi() {
        return documentApi;
    }

    @Override
    public SearchApi createSearchApi() {
        return searchApi;
    }

    @Override
    public SearchFunctionStorageApi createSearchFunctionApi() {
        return searchFunctionApi;
    }

    @Override
    public SharingApi createSharingApi() {
        return sharingApi;
    }

    @Override
    public DirectoryApi createDirectoryApi() {
        return directoryApi;
    }

}
