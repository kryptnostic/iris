package com.kryptnostic.api.v1.client;

import retrofit.http.Body;
import retrofit.http.GET;
import retrofit.http.POST;
import retrofit.http.Path;

import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.BasicResponse;
import com.kryptnostic.api.v1.models.response.DocumentResponse;

public interface KryptnosticSearch {
    /**
     * Upload a document
     * 
     * @param document
     * @return The ID of the newly saved document
     */
    @POST("/document")
    BasicResponse<String> uploadDocument(@Body DocumentRequest document);
    
    /**
     * Update a document
     * 
     * @param document
     * @return The ID of the newly saved document
     */
    @POST("/document/{id}")
    BasicResponse<String> updateDocument(@Path("id") String id, @Body DocumentRequest document);
    
    /**
     * Retrieve a document's text
     * @param id
     * @return
     */
    @GET("/document/{id}")
    DocumentResponse getDocument(@Path("id") String id);
    
    /**
     * Upload damn metaz
     * @param metadata
     * @return
     */
    @POST("/metadata")
    BasicResponse<Void> uploadMetadata(@Body MetadataRequest metadata);
}
