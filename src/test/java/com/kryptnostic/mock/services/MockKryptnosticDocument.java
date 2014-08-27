package com.kryptnostic.mock.services;

import org.junit.Assert;

import com.google.common.base.Preconditions;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.models.response.BasicResponse;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.models.request.DocumentRequest;
import com.kryptnostic.storage.v1.models.response.DocumentResponse;

/**
 * Mock KryptnosticStorage service for client testing. Validates input params and returns mock responses.
 * 
 * @author Nick Hewitt
 */
public class MockKryptnosticDocument implements DocumentApi {
    private final MockDocumentService documentService = new MockDocumentService();

    private final Integer OK_STATUS = 200;

    @Override
    public BasicResponse<String> uploadDocument(DocumentRequest document) throws BadRequestException {
        Preconditions.checkArgument(document != null, "document cannot be null.");
        validateDocumentRequest(document);
        String id = documentService.save(document.getDocument());
        return new BasicResponse<String>(id, OK_STATUS, true);
    }

    @Override
    public BasicResponse<String> updateDocument(String id, DocumentRequest document) throws ResourceNotFoundException {
        Preconditions.checkArgument(document != null, "document cannot be null.");
        Preconditions.checkArgument(id != null, "id cannot be null.");
        validateDocumentRequest(document);
        documentService.update(id, document.getDocument());
        return new BasicResponse<String>(id, OK_STATUS, true);
    }

    @Override
    public DocumentResponse getDocument(String id) throws ResourceNotFoundException {
        Preconditions.checkArgument(id != null, "id cannot be null.");
        String document = documentService.get(id);
        if (document == null) {
            throw new ResourceNotFoundException("Document with id " + id + " does not exist");
        }
        return new DocumentResponse(document, OK_STATUS, true);
    }

    private void validateDocumentRequest(DocumentRequest document) {
        Assert.assertNotNull(document.getDocument());
    }

}
