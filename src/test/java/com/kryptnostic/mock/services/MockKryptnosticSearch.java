package com.kryptnostic.mock.services;

import java.util.Arrays;
import java.util.Random;

import org.junit.Assert;
import org.mockito.Mockito;

import com.google.common.collect.ImmutableList;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
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

    private Random r = new Random(0);

    public MockKryptnosticSearch() {
        Metadatum pojoMockMetadata = Mockito.mock(Metadatum.class);

        Integer score = 2;
        String date = "testdate";
        mockResult = new SearchResultResponse(Arrays.asList(new SearchResult(ImmutableList.of(pojoMockMetadata), score,
                date)), 200, true);
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
