package com.kryptnostic.mock.services;

import java.util.Arrays;

import org.junit.Assert;
import org.mockito.Mockito;

import com.google.common.collect.ImmutableList;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.kodex.v1.models.Encryptable;
import com.kryptnostic.kodex.v1.models.Encryptable.EncryptionScheme;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.search.v1.models.SearchResult;
import com.kryptnostic.search.v1.models.request.SearchRequest;
import com.kryptnostic.search.v1.models.response.SearchResultResponse;

/**
 * Mock implementation of KryptnosticSearch for testing.
 * 
 * @author Nick Hewitt
 *
 */
// TODO replace with search on actual metadata
public class MockKryptnosticSearch implements SearchApi {
    private final SearchResultResponse mockResult;

    public MockKryptnosticSearch() {
        Metadatum pojoMockMetadata = Mockito.mock(Metadatum.class);
        // TODO: Change to AES
        Encryptable<Metadatum> encrypted = new Encryptable<Metadatum>(pojoMockMetadata, EncryptionScheme.FHE);

        Integer score = 2;
        String date = "testdate";
        mockResult = new SearchResultResponse(
                Arrays.asList(new SearchResult(ImmutableList.of(encrypted), score, date)), 200, true);
    }

    /**
     * Assert required params in SearchRequest.
     */
    private void validateRequest(SearchRequest req) {
        Assert.assertNotNull(req.getSearchToken());
    }

    @Override
    public SearchResultResponse search(SearchRequest request) {
        validateRequest(request);
        return mockResult;
    }

}
