package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;
import retrofit.client.Client;

import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.kodex.v1.authentication.PreauthenticationRequestInterceptor;
import com.kryptnostic.kodex.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.kodex.v1.security.SecurityService;

public class KryptnosticRestAdapter {

    private static final Logger logger = LoggerFactory.getLogger( KryptnosticRestAdapter.class );

    public static RestAdapter create( Client client, String url, SecurityService securityService ) {
        return builder( url, securityService ).setClient( client ).build();
    }

    public static RestAdapter create( String url, SecurityService securityService ) {
        // OkHttpClient client = new OkHttpClient();
        // client.setReadTimeout( 0, TimeUnit.MILLISECONDS );
        // client.setConnectTimeout( 0, TimeUnit.MILLISECONDS );

        return createWithDefaultClient(url, securityService);
    }

    public static RestAdapter createWithDefaultClient( String url, SecurityService securityService ) {
        return builder( url, securityService ).build();
    }

    public static RestAdapter.Builder builder( String url, SecurityService securityService ) {
        return new RestAdapter.Builder()
                .setConverter( new JacksonConverter( securityService.getSecurityConfigurationMapping() ) )
                .setEndpoint( url )

                .setRequestInterceptor(
                        new PreauthenticationRequestInterceptor( securityService.getUserKey(), securityService
                                .getUserCredential() ) ).setErrorHandler( new DefaultErrorHandler() )
                .setLogLevel( LogLevel.FULL ).setLog( new RestAdapter.Log() {
                    @Override
                    public void log( String msg ) {
                        logger.debug( msg );
                    }
                } );
    }
}
