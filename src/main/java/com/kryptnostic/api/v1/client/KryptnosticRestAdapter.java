package com.kryptnostic.api.v1.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;
import retrofit.client.Client;
import retrofit.converter.Converter;

import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.directory.v1.principal.UserKey;
import com.kryptnostic.kodex.v1.authentication.PreauthenticationRequestInterceptor;
import com.kryptnostic.kodex.v1.client.KryptnosticConnection;
import com.kryptnostic.kodex.v1.exceptions.DefaultErrorHandler;

public final class KryptnosticRestAdapter {
    private KryptnosticRestAdapter() {}

    private static final Logger logger = LoggerFactory.getLogger( KryptnosticRestAdapter.class );

    public static RestAdapter create( Client client, KryptnosticConnection credentialService ) {
        return builder( credentialService, new JacksonConverter( credentialService.getCryptoServiceLoader() ) )
                .setClient( client ).build();
    }

    public static RestAdapter create( KryptnosticConnection securityService ) {
        return createWithDefaultClient( securityService );
    }

    public static RestAdapter createWithDefaultClient( KryptnosticConnection credentialService ) {
        return builder( credentialService, new JacksonConverter( credentialService.getCryptoServiceLoader() ) ).build();
    }

    public static RestAdapter createWithDefaultJacksonConverter( KryptnosticConnection credentialService ) {
        return builder( credentialService, new JacksonConverter() ).build();
    }

    public static RestAdapter createWithDefaultJacksonConverter( String url, UserKey user, String userCredential ) {
        return builder( url, user, userCredential, new JacksonConverter() ).build();
    }

    public static RestAdapter createWithDefaultJacksonConverter(
            String url,
            UserKey user,
            String userCredential,
            Client client ) {
        return builder( url, user, userCredential, new JacksonConverter() ).setClient( client ).build();
    }

    public static RestAdapter createWithNoAuthAndDefaultJacksonConverter( String url, Client client ) {
        return new RestAdapter.Builder().setConverter( new JacksonConverter() ).setEndpoint( url )
                .setErrorHandler( new DefaultErrorHandler() ).setLogLevel( LogLevel.FULL ).setClient( client )
                .setLog( new RestAdapter.Log() {
                    @Override
                    public void log( String msg ) {
                        logger.debug( msg.replaceAll( "%", "[percent]" ) );
                    }
                } ).build();
    }

    public static RestAdapter.Builder builder( KryptnosticConnection credentialService, Converter converter ) {
        return builder(
                credentialService.getUrl(),
                credentialService.getUserKey(),
                credentialService.getUserCredential(),
                converter );
    }

    public static RestAdapter.Builder builder( String url, UserKey user, String userCredential, Converter converter ) {
        return new RestAdapter.Builder().setConverter( converter ).setEndpoint( url )
                .setRequestInterceptor( new PreauthenticationRequestInterceptor( user, userCredential ) )
                .setErrorHandler( new DefaultErrorHandler() ).setLogLevel( LogLevel.FULL )
                .setLog( new RestAdapter.Log() {
                    @Override
                    public void log( String msg ) {
                        logger.debug( msg.replaceAll( "%", "[percent]" ) );
                    }
                } );
    }
}
