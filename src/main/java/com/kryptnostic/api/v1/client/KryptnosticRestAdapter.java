package com.kryptnostic.api.v1.client;

import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.Log;
import retrofit.RestAdapter.LogLevel;
import retrofit.client.Client;
import retrofit.client.OkClient;
import retrofit.client.Request;
import retrofit.client.Response;
import retrofit.mime.TypedByteArray;

import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.kodex.v1.authentication.PreauthenticationRequestInterceptor;
import com.kryptnostic.kodex.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.squareup.okhttp.OkHttpClient;

public class KryptnosticRestAdapter {

    private static final Logger logger = LoggerFactory.getLogger( KryptnosticRestAdapter.class );

    public static RestAdapter create( Client client, String url, SecurityService securityService ) {
        // connection
        RestAdapter restAdapter = new RestAdapter.Builder()
                .setConverter( new JacksonConverter( securityService.getSecurityConfigurationMapping() ) )
                .setEndpoint( url )
                .setClient( client )
                .setRequestInterceptor(
                        new PreauthenticationRequestInterceptor( securityService.getUserKey(), securityService
                                .getUserCredential() ) ).setErrorHandler( new DefaultErrorHandler() )
                .setLogLevel( LogLevel.FULL ).setLog( new RestAdapter.Log() {
                    @Override
                    public void log( String msg ) {
                        logger.debug( msg );
                    }
                } ).build();

        return restAdapter;
    }

    public static RestAdapter create( String url, SecurityService securityService ) {
        OkHttpClient client = new OkHttpClient();
        client.setReadTimeout( 0, TimeUnit.MILLISECONDS );
        client.setConnectTimeout( 0, TimeUnit.MILLISECONDS );

        return create( new OkClient( client ), url, securityService );
    }

    public static RestAdapter createMockAdapter( String url, SecurityService securityService ) {
        Client client = new Client() {

            @Override
            public Response execute( Request request ) throws IOException {
                URI uri = URI.create( request.getUrl() );

                logger.debug( "MOCK SERVER", "fetching uri: " + uri.toString() );

                String responseString = "";

                if ( uri.getPath().equals( "/path/of/interest" ) ) {
                    responseString = "JSON STRING HERE";
                } else {
                    responseString = "OTHER JSON RESPONSE STRING";
                }

                return new Response( request.getUrl(), 200, "nothing", Collections.EMPTY_LIST, new TypedByteArray(
                        "application/json",
                        responseString.getBytes() ) );
            }
        };

        return create( client, url, securityService );
    }
}
