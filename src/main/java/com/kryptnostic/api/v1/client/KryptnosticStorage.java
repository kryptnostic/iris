package com.kryptnostic.api.v1.client;

import retrofit.http.Body;
import retrofit.http.GET;
import retrofit.http.POST;
import retrofit.http.Path;

import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.BasicResponse;
import com.kryptnostic.api.v1.models.response.DocumentResponse;

public interface KryptnosticStorage {
    String DOCUMENT = "/document";
    String METADATA = "/metadata";
    String ID = "id";

    /**
     * Upload a document
     * 
     * @param document
     * @return The ID of the newly saved document
     */
    @POST(DOCUMENT)
    BasicResponse<String> uploadDocument(@Body DocumentRequest document) throws BadRequestException;

    /**
     * Update a document
     * 
     * @param document
     * @return The ID of the newly saved document
     */
    @POST(DOCUMENT + "/{" + ID + "}")
    BasicResponse<String> updateDocument(@Path(ID) String id, @Body DocumentRequest document)
            throws ResourceNotFoundException;

    /**
     * Retrieve a document's text
     * 
     * @param id
     * @return
     */
    @GET(DOCUMENT + "/{" + ID + "}")
    DocumentResponse getDocument(@Path(ID) String id) throws ResourceNotFoundException;

    /**
     * Upload damn metaz
     * 
     * @param metadata
     * @return
     */
    @POST(METADATA)
    BasicResponse<String> uploadMetadata(@Body MetadataRequest metadata) throws BadRequestException;
}
