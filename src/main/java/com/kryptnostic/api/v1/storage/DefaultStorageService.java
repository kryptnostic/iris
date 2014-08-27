package com.kryptnostic.api.v1.storage;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.kryptnostic.api.v1.client.web.DocumentApi;
import com.kryptnostic.api.v1.client.web.MetadataApi;
import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.indexing.metadata.Metadata;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.models.IndexableMetadata;
import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.ResponseKey;

public class DefaultStorageService implements StorageService {
    private static final Logger log = LoggerFactory.getLogger(StorageService.class);

    private final DocumentApi documentApi;
    private final MetadataApi metadataApi;
    private final MetadataKeyService keyService;
    private final IndexingService indexingService;

    public DefaultStorageService(DocumentApi documentApi, MetadataApi metadataApi, MetadataKeyService keyService,
            IndexingService indexingService) {
        this.documentApi = documentApi;
        this.metadataApi = metadataApi;
        this.keyService = keyService;
        this.indexingService = indexingService;
    }

    @Override
    public String uploadDocument(String document) throws BadRequestException {
        String id = documentApi.uploadDocument(new DocumentRequest(document)).getData();

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
        metadataApi.uploadMetadata(req);

        return id;
    }

    @Override
    public String updateDocument(String id, String document) throws ResourceNotFoundException {
        return documentApi.updateDocument(id, new DocumentRequest(document)).getData();
    }

    @Override
    public String getDocument(String id) throws ResourceNotFoundException {
        return documentApi.getDocument(id).getData().get(ResponseKey.DOCUMENT_KEY);
    }

}
