package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.http.HttpStatus;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.kryptnostic.api.v1.security.IrisConnection;
import com.kryptnostic.crypto.v1.keys.Kodex.SealedKodexException;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotLockedException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.sharing.v1.DocumentId;
import com.kryptnostic.storage.v1.StorageClient;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.DocumentBlock;
import com.kryptnostic.storage.v1.models.request.AesEncryptableBase;
import com.kryptnostic.storage.v1.models.request.DocumentCreationRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;
import com.kryptnostic.users.v1.UserKey;

public class DefaultStorageServiceTests extends AesEncryptableBase {

    private StorageClient storageService;
    private UserKey       userKey;

    @Before
    public void setup() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException, SealedKodexException, IOException, SignatureException, Exception {
        userKey = new UserKey( "krypt", "sina" );
        initImplicitEncryption();
    }

    @Test
    public void uploadingWithoutMetadataTest() throws BadRequestException, ResourceNotFoundException,
            ResourceNotLockedException, IrisException, SecurityConfigurationException, ResourceLockedException,
            NoSuchAlgorithmException {
        DocumentApi documentApi = Mockito.mock( DocumentApi.class );
        MetadataApi metadataApi = Mockito.mock( MetadataApi.class );
        KryptnosticContext context = Mockito.mock( KryptnosticContext.class );

        Mockito.when( context.getSecurityService() ).thenReturn(
                new IrisConnection( pair, kodex, crypto, userKey, null, null ) );

        storageService = new DefaultStorageClient( context, documentApi, metadataApi );

        Mockito.when( documentApi.createPendingDocument( Mockito.any( DocumentCreationRequest.class ) ) ).then(
                new Answer<BasicResponse<DocumentId>>() {

                    @Override
                    public BasicResponse<DocumentId> answer( InvocationOnMock invocation ) throws Throwable {
                        return new BasicResponse<DocumentId>(
                                new DocumentId( "document1", userKey ),
                                HttpStatus.SC_OK,
                                true );
                    }

                } );

        Mockito.when( documentApi.updateDocument( Mockito.anyString(), Mockito.any( DocumentBlock.class ) ) ).then(
                new Answer<BasicResponse<DocumentId>>() {

                    @Override
                    public BasicResponse<DocumentId> answer( InvocationOnMock invocation ) throws Throwable {
                        return new BasicResponse<DocumentId>(
                                new DocumentId( "document1", userKey ),
                                HttpStatus.SC_OK,
                                true );
                    }

                } );

        Mockito.when( metadataApi.uploadMetadata( Mockito.any( MetadataRequest.class ) ) ).then( new Answer<String>() {

            @Override
            public String answer( InvocationOnMock invocation ) throws Throwable {
                Assert.fail( "No metadata should be uploaded" );
                return null;
            }

        } );

        storageService.uploadDocumentWithoutMetadata( "test" );

        storageService.updateDocumentWithoutMetadata( "test", "test" );
    }
}
