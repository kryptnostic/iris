package com.kryptnostic.api.v1.models;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SearchResult {
    private static final String METADATA = "metadata";
    private static final String SCORE = "score";
    private static final String DATE = "date";
    
    private final String metadata;
    private final Integer score;
    private final String date;

    @JsonCreator
    public SearchResult(
            @JsonProperty( METADATA ) String metadata, 
            @JsonProperty( SCORE ) Integer score, 
            @JsonProperty( DATE ) String date) {
        this.metadata = metadata;
        this.score = score;
        this.date = date;
    }

    @JsonProperty( METADATA ) 
    public String getMetadata() {
        return metadata;
    }

    @JsonProperty( SCORE ) 
    public Integer getScore() {
        return score;
    }

    @JsonProperty( DATE ) 
    public String getDate() {
        return date;
    }
}
