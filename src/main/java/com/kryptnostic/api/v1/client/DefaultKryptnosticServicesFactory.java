package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.directory.v1.http.UserDirectoryApi;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.sharing.v1.http.SharingApi;

import retrofit.RestAdapter;

public class DefaultKryptnosticServicesFactory implements KryptnosticServicesFactory {
    private final static Logger    logger = LoggerFactory.getLogger( DefaultKryptnosticServicesFactory.class );

    private final SharingApi       sharingApi;
    private final UserDirectoryApi     userDirectoryApi;

    public DefaultKryptnosticServicesFactory( KryptnosticConnection credentialService ) {
        this( KryptnosticRestAdapter.create( credentialService ) );
    }

    public DefaultKryptnosticServicesFactory( RestAdapter restAdapter ) {
        logger.debug( "Starting generation of facades for KryptnosticServices." );
        sharingApi = restAdapter.create( SharingApi.class );
        userDirectoryApi = restAdapter.create( UserDirectoryApi.class );
        logger.debug( "Finishing generation of facades for KryptnosticServices." );
    }

    @Override
    public SharingApi createSharingApi() {
        return sharingApi;
    }

    @Override
    public UserDirectoryApi createDirectoryApi() {
        return userDirectoryApi;
    }

}
