package com.kryptnostic.api.v1.client;

import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;

public interface KryptnosticConnection {
    String uploadDocument(String document);
    String updateDocument(String id, String document);
    String getDocument(String id) throws ResourceNotFoundException;
}
