package com.kryptnostic.api.v1.storage;

import java.io.IOException;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.storage.v1.StorageService;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.request.AesEncryptableBase;

public class DefaultStorageServiceTests extends AesEncryptableBase {

    private StorageService storageService;

    @Before
    public void setup() {
        initImplicitEncryption();
    }

    @Test
    public void uploadingWithoutMetadataTest() throws BadRequestException, SecurityConfigurationException, IOException {
        DocumentApi documentApi = Mockito.mock(DocumentApi.class);
        MetadataApi metadataApi = Mockito.mock(MetadataApi.class);
        KryptnosticContext context = Mockito.mock(KryptnosticContext.class);
        storageService = new DefaultStorageService(documentApi, metadataApi, new BalancedMetadataKeyService(context),
                new BaseIndexingService(), config);
        
        Mockito.when(metadataApi.uploadMetadata(Mockito.any())).then(new Answer<String>() {

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
