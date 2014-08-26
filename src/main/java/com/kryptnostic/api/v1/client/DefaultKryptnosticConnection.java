package com.kryptnostic.api.v1.client;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.indexing.metadata.Metadata;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.models.IndexableMetadata;
import com.kryptnostic.api.v1.models.SearchResult;
import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.request.SearchRequest;
import com.kryptnostic.api.v1.models.response.ResponseKey;

// TODO: exception handling
public class DefaultKryptnosticConnection implements KryptnosticConnection {
    private static final Logger log = LoggerFactory.getLogger(KryptnosticConnection.class);
    
    @Inject
    private KryptnosticStorage storageService;
    @Inject
    private KryptnosticSearch searchService;
    @Inject
    private MetadataKeyService keyService;
    @Inject
    private IndexingService indexingService;

    @Override
    public String uploadDocument(String document) throws BadRequestException {
        String id = storageService.uploadDocument(new DocumentRequest(document)).getData();

        // metadata stuff now
        // index + map tokens
        Set<Metadatum> metadata = indexingService.index(id, document);
        Metadata keyedMetadata = keyService.mapTokensToKeys(metadata);

        // format for metadata upload
        Collection<IndexableMetadata> metadataIndex = Lists.newArrayList();
        for (Map.Entry<String, List<Metadatum>> m : keyedMetadata.getMetadataMap().entrySet()) {
            log.debug("list" + m.getValue().toString());
            String key = m.getKey();
            String value = m.getValue().toString();
            metadataIndex.add(new IndexableMetadata(key, value));
        }
        MetadataRequest req = new MetadataRequest(metadataIndex);
        log.debug("generated metadata " + keyedMetadata);
        storageService.uploadMetadata(req);

        return id;
    }

    @Override
    public String updateDocument(String id, String document) throws ResourceNotFoundException {
        return storageService.updateDocument(id, new DocumentRequest(document)).getData();
    }

    @Override
    public String getDocument(String id) throws ResourceNotFoundException {
        return storageService.getDocument(id).getData().get(ResponseKey.DOCUMENT_KEY);
    }
    
}
