package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;

import com.kryptnostic.directory.v1.KeyApi;
import com.kryptnostic.directory.v1.UsersApi;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.sharing.v1.requests.SharingApi;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger     logger = LoggerFactory.getLogger( DefaultKryptnosticServicesFactory.class );

    private final MetadataApi       metadataService;
    private final DocumentApi       documentService;
    private final SearchApi         searchService;
    private final SearchFunctionApi searchFunctionService;
    private final SharingApi        sharingService;
    private final KeyApi            keyService;
    private final UsersApi          usersService;

    public DefaultKryptnosticServicesFactory( KryptnosticConnection credentialService ) {
        this( KryptnosticRestAdapter.create( credentialService ) );
    }

    public DefaultKryptnosticServicesFactory( RestAdapter restAdapter ) {
        documentService = restAdapter.create( DocumentApi.class );
        metadataService = restAdapter.create( MetadataApi.class );
        searchService = restAdapter.create( SearchApi.class );
        searchFunctionService = restAdapter.create( SearchFunctionApi.class );
        sharingService = restAdapter.create( SharingApi.class );
        keyService = restAdapter.create( KeyApi.class );
        usersService = restAdapter.create( UsersApi.class );
    }

    @Override
    public MetadataApi createMetadataApi() {
        return metadataService;
    }

    @Override
    public DocumentApi createDocumentApi() {
        return documentService;
    }

    @Override
    public SearchApi createSearchApi() {
        return searchService;
    }

    @Override
    public SearchFunctionApi createSearchFunctionApi() {
        return searchFunctionService;
    }

    @Override
    public SharingApi createSharingApi() {
        return sharingService;
    }

    @Override
    public KeyApi createKeyApi() {
        return keyService;
    }

    @Override
    public UsersApi createUsersApi() {
        return usersService;
    }

}
