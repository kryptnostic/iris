package com.kryptnostic.api.v1.client;

import java.util.Set;

import com.kryptnostic.directory.v1.DirectoryClient;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.directory.v1.principal.UserKey;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.sharing.v1.models.NotificationPreference;

public class DefaultDirectoryClient implements DirectoryClient {

    private final DirectoryApi       directoryApi;
    private final KryptnosticContext context;

    public DefaultDirectoryClient( KryptnosticContext context, DirectoryApi directoryApi ) {
        this.context = context;
        this.directoryApi = directoryApi;
    }

    @Override
    public Set<UserKey> listUserInRealm( String realm ) {
        return directoryApi.listUserInRealm( realm );
    }

    @Override
    public PublicKeyEnvelope getPublicKey( String username ) throws ResourceNotFoundException {
        return directoryApi.getPublicKey( username );
    }

    @Override
    public NotificationPreference getNotificationPreference() {
        return directoryApi.getNotificationPreference().getData();
    }

    @Override
    public void setNotificationPreference( NotificationPreference preference ) {
        directoryApi.setNotificationPreference( preference );
    }

}
