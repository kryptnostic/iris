package com.kryptnostic.api.v1.models.request;

import java.util.Collection;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.models.IndexableMetadata;

public class MetadataRequest {
    private Collection<IndexableMetadata> metadata;

    public MetadataRequest() {
        metadata = Lists.newArrayList();
    }
    
    public Collection<IndexableMetadata> getMetadata() {
        return new ImmutableList.Builder<IndexableMetadata>().addAll(metadata).build();
    }

    public void addMetadata(IndexableMetadata m) {
        metadata.add(m);
    }
}
