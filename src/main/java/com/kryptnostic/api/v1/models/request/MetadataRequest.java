package com.kryptnostic.api.v1.models.request;

import java.util.Collection;
import java.util.Collections;

import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.models.IndexableMetadata;

public class MetadataRequest {
    private final Collection<IndexableMetadata> metadata;

    public MetadataRequest() {
        metadata = Lists.newArrayList();
    }

    public Collection<IndexableMetadata> getMetadata() {
        return Collections.unmodifiableCollection(metadata);
    }

    public void addMetadata(IndexableMetadata m) {
        metadata.add(m);
    }
}
