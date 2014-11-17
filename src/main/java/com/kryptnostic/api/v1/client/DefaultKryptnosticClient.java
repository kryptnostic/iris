package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.api.v1.search.DefaultSearchClient;
import com.kryptnostic.api.v1.sharing.SharingManager;
import com.kryptnostic.api.v1.storage.DefaultStorageClient;
import com.kryptnostic.directory.v1.UsersApi;
import com.kryptnostic.kodex.v1.client.KryptnosticClient;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.client.KryptnosticServicesFactory;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.marshalling.DeflatingJacksonMarshaller;
import com.kryptnostic.kodex.v1.security.KryptnosticConnection;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.search.v1.models.SearchResult;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.sharing.v1.SharingClient;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.users.v1.UserKey;

public class DefaultKryptnosticClient implements KryptnosticClient {
    private static DeflatingJacksonMarshaller marshaller = new DeflatingJacksonMarshaller();
    private static ObjectMapper               mapper     = KodexObjectMapperFactory.getObjectMapper();

    private final SearchClient                searchClient;
    private final KryptnosticContext          context;
    private final UsersApi                    usersClient;
    private final StorageClient               storageClient;
    private final SharingClient               sharingClient;

    public DefaultKryptnosticClient( KryptnosticServicesFactory factory, KryptnosticConnection securityService ) throws IrisException,
            ResourceNotFoundException {
        this.context = new DefaultKryptnosticContext(
                factory.createSearchFunctionApi(),
                factory.createSharingApi(),
                factory.createKeyApi(),
                securityService );

        this.storageClient = new DefaultStorageClient(
                context,
                factory.createDocumentApi(),
                factory.createMetadataApi() );
        this.searchClient = new DefaultSearchClient( context, factory.createSearchApi() );
        this.usersClient = factory.createUsersApi();
        this.sharingClient = new SharingManager( securityService, context, factory.createSharingApi() );
    }

    @Override
    public Collection<SearchResult> search( String query ) {
        return searchClient.search( query );
    }

    @Override
    public String uploadDocumentWithMetadata( String document ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        return storageClient.uploadDocumentWithMetadata( document );
    }

    @Override
    public String uploadDocumentWithoutMetadata( String document ) throws BadRequestException,
            SecurityConfigurationException, IrisException {
        return storageClient.uploadDocumentWithoutMetadata( document );
    }

    @Override
    public String updateDocumentWithMetadata( String id, String document ) throws ResourceNotFoundException,
            BadRequestException, SecurityConfigurationException, ResourceLockedException, IrisException {
        return storageClient.updateDocumentWithMetadata( id, document );
    }

    @Override
    public String updateDocumentWithoutMetadata( String id, String document ) throws BadRequestException,
            SecurityConfigurationException, ResourceNotFoundException, ResourceLockedException, IrisException {
        return storageClient.updateDocumentWithoutMetadata( id, document );
    }

    @Override
    public Document getDocument( DocumentId id ) throws ResourceNotFoundException {
        return storageClient.getDocument( id );
    }

    @Override
    public KryptnosticContext getContext() {
        return this.context;
    }

    @Override
    public String uploadMetadata( MetadataRequest metadata ) throws BadRequestException {
        return storageClient.uploadMetadata( metadata );
    }

    @Override
    public Collection<DocumentId> getDocumentIds() {
        return storageClient.getDocumentIds();
    }

    @Override
    public Map<Integer, String> getDocumentFragments( DocumentId id, List<Integer> offsets, int characterWindow )
            throws ResourceNotFoundException, SecurityConfigurationException, IrisException {
        return storageClient.getDocumentFragments( id, offsets, characterWindow );
    }

    @Override
    public Set<UserKey> listUserInRealm( String realm ) {
        return usersClient.listUserInRealm( realm );
    }

    @Override
    public void deleteMetadata( DocumentId id ) {
        storageClient.deleteMetadata( id );
    }

    @Override
    public void deleteDocument( DocumentId id ) {
        storageClient.deleteDocument( id );
    }

    public SharingClient getSharingClient() {
        return sharingClient;
    }

    @Override
    public List<Document> getDocuments( List<DocumentId> ids ) throws ResourceNotFoundException {
        return storageClient.getDocuments( ids );
    }

}
