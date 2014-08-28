package com.kryptnostic.api.v1.storage;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.google.common.collect.Lists;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.storage.v1.StorageService;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.request.DocumentRequest;
import com.kryptnostic.storage.v1.models.request.IndexableMetadata;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

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
        for (Map.Entry<BitVector, List<Metadatum>> m : keyedMetadata.getMetadataMap().entrySet()) {
            log.debug("list" + m.getValue().toString());
            BitVector key = m.getKey();
            for (Metadatum subMeta : m.getValue()) {
                metadataIndex.add(new IndexableMetadata(key, subMeta));
            }
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
    public Document getDocument(String id) throws ResourceNotFoundException {
        return documentApi.getDocument(id).getData();
    }

}
