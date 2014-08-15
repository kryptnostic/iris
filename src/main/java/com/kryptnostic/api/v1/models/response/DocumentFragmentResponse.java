package com.kryptnostic.api.v1.models.response;

import java.util.HashMap;
import java.util.Map;

public class DocumentFragmentResponse extends BasicResponse<Map<String, Object>> {

    public DocumentFragmentResponse() {
        data = new HashMap<String, Object>();
    }

    public DocumentFragmentResponse(Map<Integer, String> fragments, int status, boolean success) {
        super(new HashMap<String, Object>(), status, success);
        data.put(ResponseKey.FRAGMENT_KEY, fragments);
    }
}
