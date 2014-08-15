package com.kryptnostic.api.v1.models.request;

public class DocumentRequest {
    private String document;

    public DocumentRequest() {

    }

    public DocumentRequest(String document) {
        this.document = document;
    }

    public String getDocument() {
        return document;
    }

    public void setDocument(String document) {
        this.document = document;
    }
}
