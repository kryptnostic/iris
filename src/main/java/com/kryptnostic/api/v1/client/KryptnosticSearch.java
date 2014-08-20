package com.kryptnostic.api.v1.client;

import retrofit.http.Body;
import retrofit.http.POST;

import com.kryptnostic.api.v1.models.SearchResult;
import com.kryptnostic.api.v1.models.request.SearchRequest;

public interface KryptnosticSearch {
    String SEARCH = "/search";

    /**
     * Upload a document
     * 
     * @param document
     * @return The ID of the newly saved document
     */

    @POST(SEARCH)
    SearchResult search(@Body SearchRequest request );
}
