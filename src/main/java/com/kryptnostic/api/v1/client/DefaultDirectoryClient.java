package com.kryptnostic.api.v1.client;

import java.util.UUID;

import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.directory.v1.DirectoryClient;
import com.kryptnostic.directory.v1.http.DirectoryApi;
import com.kryptnostic.directory.v1.model.response.PublicKeyEnvelope;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.sharing.v1.models.NotificationPreference;

public class DefaultDirectoryClient implements DirectoryClient {

    private final DirectoryApi directoryApi;

    // This is here so when things are added in the future, it is possible to use the context to access relevant
    // classes.

    public DefaultDirectoryClient( KryptnosticConnection connection ) {
        this.directoryApi = connection.getDirectoryApi();
    }

    @Override
    public Iterable<UUID> listUsersInRealm( String realm ) {
        return directoryApi.listUserInRealm( realm );
    }

    @Override
    public PublicKeyEnvelope getPublicKey( UUID id ) throws ResourceNotFoundException {
        return directoryApi.getPublicKey( id );
    }

    @Deprecated
    @Override
    public NotificationPreference getNotificationPreference() {
        return directoryApi.getNotificationPreference().getData();
    }

    @Deprecated
    @Override
    public void setNotificationPreference( NotificationPreference preference ) {
        directoryApi.setNotificationPreference( preference );
    }

}
