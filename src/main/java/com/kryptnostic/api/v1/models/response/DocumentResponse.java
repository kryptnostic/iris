package com.kryptnostic.api.v1.models.response;

import java.util.HashMap;
import java.util.Map;

public class DocumentResponse extends BasicResponse<Map<String, String>> {

    public DocumentResponse() {
        data = new HashMap<String, String>();
    }

    public DocumentResponse(String document, int status, boolean success) {
        super(new HashMap<String, String>(), status, success);
        data.put(ResponseKey.DOCUMENT_KEY, document);
    }

}
