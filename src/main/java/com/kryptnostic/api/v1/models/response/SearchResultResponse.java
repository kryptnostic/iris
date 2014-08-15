package com.kryptnostic.api.v1.models.response;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.kryptnostic.api.v1.models.SearchResult;

public class SearchResultResponse extends BasicResponse<Map<String, Object>> {

    public SearchResultResponse() {
        data = new HashMap<String, Object>();
    }

    public SearchResultResponse(List<SearchResult> results, Integer resultCount, int status, boolean success) {
        super(new HashMap<String, Object>(), status, success);
        data.put(ResponseKey.RESULT_KEY, results);
        data.put(ResponseKey.RESULT_COUNT_KEY, resultCount);
    }

}
