package com.kryptnostic.api.v1.client;

import java.util.UUID;

import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.directory.v1.DirectoryClient;
import com.kryptnostic.directory.v1.http.UserDirectoryApi;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.v2.storage.api.KeyStorageApi;

public class DefaultDirectoryClient implements DirectoryClient {

    private final UserDirectoryApi userDirectoryApi;
    private final KeyStorageApi keyStorageApi;


    // This is here so when things are added in the future, it is possible to use the context to access relevant
    // classes.

    public DefaultDirectoryClient( KryptnosticConnection connection ) {
        this.userDirectoryApi = connection.getDirectoryApi();
        this.keyStorageApi = connection.getKeyStorageApi();
    }

    @Override
    public Iterable<UUID> listUsersInRealm( String realm ) throws BadRequestException {
        return userDirectoryApi.listUserInRealm( realm );
    }

    @Override
    public byte[] getPublicKey( UUID id ) {
        return keyStorageApi.getRSAPublicKey( id );
    }

}
