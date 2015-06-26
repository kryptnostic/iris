package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;

import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.instrumentation.v1.MetricsApi;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.search.v1.http.SearchApi;
import com.kryptnostic.sharing.v1.http.SharingApi;
import com.kryptnostic.storage.v1.http.ObjectApi;
import com.kryptnostic.storage.v1.http.MetadataApi;
import com.kryptnostic.storage.v1.http.SearchFunctionApi;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger     logger = LoggerFactory.getLogger( DefaultKryptnosticServicesFactory.class );

    private final MetadataApi       metadataApi;
    private final ObjectApi       documentApi;
    private final SearchApi         searchApi;
    private final SearchFunctionApi searchFunctionApi;
    private final SharingApi        sharingApi;
    private final DirectoryApi      directoryApi;
    private final MetricsApi	 	metricsApi;

    public DefaultKryptnosticServicesFactory( KryptnosticConnection credentialService ) {
        this( KryptnosticRestAdapter.create( credentialService ) );
    }

    public DefaultKryptnosticServicesFactory( RestAdapter restAdapter ) {
        documentApi = restAdapter.create( ObjectApi.class );
        metadataApi = restAdapter.create( MetadataApi.class );
        searchApi = restAdapter.create( SearchApi.class );
        searchFunctionApi = restAdapter.create( SearchFunctionApi.class );
        sharingApi = restAdapter.create( SharingApi.class );
        directoryApi = restAdapter.create( DirectoryApi.class );
        metricsApi = restAdapter.create(MetricsApi.class);
    }

    @Override
    public MetadataApi createMetadataApi() {
        return metadataApi;
    }

    @Override
    public ObjectApi createDocumentApi() {
        return documentApi;
    }

    @Override
    public SearchApi createSearchApi() {
        return searchApi;
    }

    @Override
    public SearchFunctionApi createSearchFunctionApi() {
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
    
    @Override
    public MetricsApi createMetricsApi() {
        return metricsApi;
    }

}
