package com.kryptnostic.mock.services;

import java.util.List;
import java.util.Map;
import java.util.Random;

import org.junit.Assert;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.client.KryptnosticSearch;
import com.kryptnostic.api.v1.indexing.metadata.Metadata;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.models.SearchResult;
import com.kryptnostic.api.v1.models.request.SearchRequest;
import com.kryptnostic.api.v1.serialization.jackson.KodexObjectMapperFactory;
import com.kryptnostic.linear.BitUtils;

/**
 * Mock implementation of KryptnosticSearch for testing.
 * 
 * @author Nick Hewitt
 *
 */
// TODO replace with search on actual metadata
public class MockKryptnosticSearch implements KryptnosticSearch {
    private final SearchResult mockResult;
    
    private Random r = new Random(0);
    private final KodexObjectMapperFactory objectMapperFactory = new KodexObjectMapperFactory();
    
    public MockKryptnosticSearch() {
        Metadata pojoMockMetadata = new MockMetadata();
        ObjectMapper objectMapper = objectMapperFactory.getObjectMapper();
        String metadata = null;
        try {
            metadata = objectMapper.writeValueAsString(pojoMockMetadata);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        
        Integer score = 2;
        String date = "testdate";
        mockResult = new SearchResult(metadata, score, date);
    }
    
    /**
     * Validate contents of request.
     * @return SearchResult, a mock instance containing sample data.
     */
    @Override
    public SearchResult search(SearchRequest request) {
        validateRequest(request);
        return mockResult;
    }

    /**
     * Assert required params in SearchRequest.
     */
    private void validateRequest(SearchRequest request) {
        Assert.assertNotNull(request.getSearchToken());
    }
    
    /**
     * Mock implementation of Metadata.
     * 
     * @author Nick Hewitt
     *
     */
    private class MockMetadata implements Metadata {
        private final Map<String, List<Metadatum>> metadataMap;
        private final List<BitVector> nonces;
        
        private final Integer N_KEYS = 5;
        private final Integer N_METADATUM = 10;
        private final Integer N_NONCES = 10;
        
        public MockMetadata() {
            metadataMap = Maps.newHashMap();
            for (int i = 0; i < N_KEYS; i++) {
                List<Metadatum> mockMetadatumList = Lists.newArrayList();
                for (int j = 0; j < N_METADATUM; j++) {
                    mockMetadatumList.add(new MockMetadatum());
                }
                metadataMap.put("key-"+ Integer.toString(i), mockMetadatumList);
            }
            nonces = Lists.newArrayList();
            for (int i = 0; i < N_NONCES; i++) {
                nonces.add(BitUtils.randomVector(64));
            }
        }
        
        @Override
        public Map<String, List<Metadatum>> getMetadataMap() {
            return metadataMap;
        }

        @Override
        public List<BitVector> getNonces() {
            return nonces;
        }
        
    }
    
    /**
     * Mock implementation of Metadatum. 
     * @author Nick Hewitt
     *
     */
    private class MockMetadatum implements Metadatum {
        private final String documentId;
        private final String token;
        private final List<Integer> locations;
        
        private final Integer N_LOCATIONS = 25;
        
        public MockMetadatum() {
            documentId = Integer.toString(r.nextInt());
            token = Integer.toString(r.nextInt());
            locations = Lists.newArrayList();
            for (int i = 0; i < N_LOCATIONS; i++) {
                locations.add(r.nextInt());
            }
        }
        
        @Override
        public String getDocumentId() {
            return documentId;
        }

        @Override
        public String getToken() {
            return token;
        }

        @Override
        public List<Integer> getLocations() {
            return locations;
        }

        @Override
        public boolean equals(Metadatum obj) {
            boolean isEqual = getDocumentId().equals(obj.getDocumentId())
                    && getToken().equals(obj.getToken())
                    && getLocations().equals(obj.getLocations());
            return isEqual;
        }
        
    }

}
