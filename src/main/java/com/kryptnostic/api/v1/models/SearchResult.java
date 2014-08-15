package com.kryptnostic.api.v1.models;

public class SearchResult {
    private String metadata;
    private Integer score;
    private String date;

    public SearchResult() {

    }

    public SearchResult(String metadata, Integer score, String date) {
        super();
        this.metadata = metadata;
        this.score = score;
        this.date = date;
    }

    public String getMetadata() {
        return metadata;
    }

    public Integer getScore() {
        return score;
    }

    public String getDate() {
        return date;
    }
}
