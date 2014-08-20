package com.kryptnostic.api.v1.client;

import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;

public interface KryptnosticSearchConnection {
    String uploadDocument(String document) throws BadRequestException;

    String updateDocument(String id, String document);

    String getDocument(String id) throws ResourceNotFoundException;
}
