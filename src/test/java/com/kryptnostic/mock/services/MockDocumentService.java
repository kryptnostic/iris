package com.kryptnostic.mock.services;

import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;

/**
 * In memory implementation of a document storage service for testing.
 * 
 * @author Nick Hewitt
 *
 */
public class MockDocumentService {
    private final Map<String, String> documentStore = Maps.newHashMap();
    private static AtomicLong idCounter = new AtomicLong(0);
    
    public String save(String document) {
        Long count = idCounter.getAndIncrement();
        String id = "DOCUMENT_" + count;
        documentStore.put(id, document);
        return id;
    }

    public String update(String id, String document) throws ResourceNotFoundException {
        if (documentStore.get(id) == null) {
            throw new ResourceNotFoundException();
        }
        documentStore.put(id, document);
        return id;
    }

    public String get(String id) throws ResourceNotFoundException {
        return documentStore.get(id);
    }
}
