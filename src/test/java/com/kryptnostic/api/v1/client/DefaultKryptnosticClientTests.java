package com.kryptnostic.api.v1.client;

import org.junit.Test;
import org.springframework.util.Assert;

import com.kryptnostic.api.v1.security.InMemorySecurityService;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.users.v1.UserKey;

public class DefaultKryptnosticClientTests {

    @Test
    public void initTest() throws IrisException {
        final SecurityService securityService = new InMemorySecurityService( new UserKey( "krypt", "sina" ), "test" );
        final KryptnosticServicesFactory factory = new DefaultKryptnosticServicesFactory(
                KryptnosticRestAdapter.createMockAdapter( "whatever", securityService ) );
        KryptnosticClient client = new DefaultKryptnosticClient( factory, securityService );

        Assert.notNull( client.getContext() );
    }

}
