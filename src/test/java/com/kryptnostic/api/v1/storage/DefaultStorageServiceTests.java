package com.kryptnostic.api.v1.storage;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.http.HttpStatus;

import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.storage.v1.StorageService;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.DocumentBlock;
import com.kryptnostic.storage.v1.models.request.AesEncryptableBase;
import com.kryptnostic.storage.v1.models.request.DocumentCreationRequest;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class DefaultStorageServiceTests extends AesEncryptableBase {

    private StorageService storageService;

    @Before
    public void setup() {
        initImplicitEncryption();
    }

    @Test
    public void uploadingWithoutMetadataTest() throws BadRequestException, SecurityConfigurationException, IOException,
            ClassNotFoundException, ResourceNotFoundException {
        DocumentApi documentApi = Mockito.mock(DocumentApi.class);
        MetadataApi metadataApi = Mockito.mock(MetadataApi.class);
        KryptnosticContext context = Mockito.mock(KryptnosticContext.class);
        storageService = new DefaultStorageService(documentApi, metadataApi, new BalancedMetadataKeyService(context),
                new BaseIndexingService(), config);

        Mockito.when(documentApi.createDocument(Mockito.any(DocumentCreationRequest.class))).then(
                new Answer<BasicResponse<String>>() {

                    @Override
                    public BasicResponse<String> answer(InvocationOnMock invocation) throws Throwable {
                        return new BasicResponse<String>("document1", HttpStatus.OK.value(), true);
                    }

                });
        
        Mockito.when(documentApi.updateDocument(Mockito.anyString(), Mockito.any(DocumentBlock.class))).then(
                new Answer<BasicResponse<String>>() {

                    @Override
                    public BasicResponse<String> answer(InvocationOnMock invocation) throws Throwable {
                        return new BasicResponse<String>("document1", HttpStatus.OK.value(), true);
                    }

                });

        Mockito.when(metadataApi.uploadMetadata(Mockito.any(MetadataRequest.class))).then(new Answer<String>() {

            @Override
            public String answer(InvocationOnMock invocation) throws Throwable {
                Assert.fail("No metadata should be uploaded");
                return null;
            }

        });

        storageService.uploadDocumentWithoutMetadata("test");

        storageService.updateDocumentWithoutMetadata("test", "test");
    }
}
