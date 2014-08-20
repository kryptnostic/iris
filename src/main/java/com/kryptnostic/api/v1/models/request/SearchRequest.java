package com.kryptnostic.api.v1.models.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Optional;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

/**
 * Search request for submittin
 * @author Matthew Tamayo-Rios <matthew@kryptnostic.com>
 */
public class SearchRequest {
    private static final String SEARCH_FUNCTION_PROPERTY = "SEARCH";
    private static final String MAX_RESULTS_PROPERTY = "MAX-RESULTS";
    private static final String PAGED_PROPERTY = "PAGED";
    
    private final SimplePolynomialFunction searchFunction;
    private final int maxResults; 
    private final boolean paged;
    
    @JsonCreator
    public SearchRequest( 
            @JsonProperty( SEARCH_FUNCTION_PROPERTY ) SimplePolynomialFunction searchFunction, 
            @JsonProperty( MAX_RESULTS_PROPERTY ) Optional<Integer>  maxResults, 
            @JsonProperty( PAGED_PROPERTY ) Optional<Boolean> paged ) {
        this.searchFunction = searchFunction;
        this.maxResults = maxResults.or( 0 ); // 0 => unlimited
        this.paged = paged.or( false ); 
    }

    @JsonProperty( SEARCH_FUNCTION_PROPERTY ) 
    public SimplePolynomialFunction getSearchFunction() {
        return searchFunction;
    }

    @JsonProperty( MAX_RESULTS_PROPERTY ) 
    public int getMaxResults() {
        return maxResults;
    }

    @JsonProperty( PAGED_PROPERTY ) 
    public boolean isPaged() {
        return paged;
    }
}
