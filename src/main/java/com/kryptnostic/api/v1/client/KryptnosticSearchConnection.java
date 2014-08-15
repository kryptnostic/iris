package com.kryptnostic.api.v1.client;


public interface KryptnosticSearchConnection {
    String uploadDocument(String document);
    String updateDocument(String id, String document);
    String getDocument(String id);
}
