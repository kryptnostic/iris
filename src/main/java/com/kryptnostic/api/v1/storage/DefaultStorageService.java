package com.kryptnostic.api.v1.storage;

import java.io.IOException;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import cern.colt.bitvector.BitVector;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.exceptions.types.BadRequestException;
import com.kryptnostic.kodex.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.kodex.v1.exceptions.types.SecurityConfigurationException;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.kodex.v1.models.AesEncryptable;
import com.kryptnostic.kodex.v1.models.Encryptable;
import com.kryptnostic.kodex.v1.models.utils.AesEncryptableUtils;
import com.kryptnostic.kodex.v1.security.SecurityConfigurationMapping;
import com.kryptnostic.storage.v1.StorageService;
import com.kryptnostic.storage.v1.client.DocumentApi;
import com.kryptnostic.storage.v1.client.MetadataApi;
import com.kryptnostic.storage.v1.models.Document;
import com.kryptnostic.storage.v1.models.DocumentBlock;
import com.kryptnostic.storage.v1.models.request.IndexedMetadata;
import com.kryptnostic.storage.v1.models.request.MetadataRequest;

public class DefaultStorageService implements StorageService {
    private static final Logger log = LoggerFactory.getLogger(StorageService.class);

    private static final int PARALLEL_NETWORK_THREADS = 4;

    private final DocumentApi documentApi;
    private final MetadataApi metadataApi;
    private final MetadataKeyService keyService;
    private final IndexingService indexingService;
    private final SecurityConfigurationMapping mapping;

    public DefaultStorageService(DocumentApi documentApi, MetadataApi metadataApi, MetadataKeyService keyService,
            IndexingService indexingService, SecurityConfigurationMapping mapping) {
        this.documentApi = documentApi;
        this.metadataApi = metadataApi;
        this.keyService = keyService;
        this.indexingService = indexingService;
        this.mapping = mapping;
    }

    @Override
    public String uploadDocument(String documentBody) throws BadRequestException, SecurityConfigurationException,
            IOException, ResourceNotFoundException {
        String id = documentApi.createDocument().getData();
        updateDocument(id, documentBody);
        return id;
    }

    @Override
    public String uploadDocumentWithoutMetadata(String documentBody) throws BadRequestException,
            SecurityConfigurationException, IOException {
        String id = documentApi.createDocument().getData();
        updateDocumentWithoutMetadata(id, documentBody);
        return id;
    }

    @Override
    public String updateDocument(String id, String documentBody) throws ResourceNotFoundException, BadRequestException,
            SecurityConfigurationException, IOException {
        updateDocumentWithoutMetadata(id, documentBody);
        // index + map tokens
        Set<Metadatum> metadata = indexingService.index(id, documentBody);
        uploadMetadata(prepareMetadata(metadata));
        return id;
    }

    @Override
    public String updateDocumentWithoutMetadata(String id, String documentBody) throws BadRequestException,
            SecurityConfigurationException, IOException {

        ExecutorService e = Executors.newFixedThreadPool(PARALLEL_NETWORK_THREADS);
        Document doc = null;
        try {
            doc = AesEncryptableUtils.createEncryptedDocument(id, documentBody, mapping);
        } catch (ClassNotFoundException e1) {
            e1.printStackTrace();
        }
        List<Future<String>> jobs = Lists.newArrayList();

        for (DocumentBlock block : doc.getBlocks()) {
            jobs.add(e.submit(new Callable<String>() {

                @Override
                public String call() throws Exception {
                    return documentApi.updateDocument(id, block).getData();
                }
            }));
        }

        for (Future<String> f : jobs) {
            try {
                log.info("Document Block Upload completed: " + f.get());
            } catch (InterruptedException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (ExecutionException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            }
        }

        return id;
    }

    @Override
    public Document getDocument(String id) throws ResourceNotFoundException {
        Document document = documentApi.getDocument(id).getData();
        return document;
    }

    @Override
    public String uploadMetadata(MetadataRequest req) throws BadRequestException {
        return metadataApi.uploadMetadata(req).getData();
    }

    private MetadataRequest prepareMetadata(Set<Metadatum> metadata) {
        Metadata keyedMetadata = keyService.mapTokensToKeys(metadata);
        log.debug("generated metadata " + keyedMetadata);

        // format for metadata upload
        Collection<IndexedMetadata> metadataIndex = Lists.newArrayList();
        for (Map.Entry<BitVector, List<Metadatum>> m : keyedMetadata.getMetadataMap().entrySet()) {
            log.debug("list" + m.getValue().toString());
            BitVector key = m.getKey();
            for (Metadatum subMeta : m.getValue()) {
                metadataIndex.add(new IndexedMetadata(key, new AesEncryptable<Metadatum>(subMeta)));
            }
        }
        return new MetadataRequest(metadataIndex);
    }

    @Override
    public Collection<String> getDocumentIds() {
        return documentApi.getDocumentIds().getData();
    }

    @Override
    public Map<Integer, String> getDocumentFragments(String id, List<Integer> offsets, int characterWindow)
            throws ResourceNotFoundException, JsonParseException, JsonMappingException, IOException,
            ClassNotFoundException, SecurityConfigurationException {
        Map<Integer, String> plain = Maps.newHashMap();
        Map<Integer, Encryptable<String>> encrypted = documentApi.getDocumentFragments(id, offsets, characterWindow)
                .getData();
        for (Entry<Integer, Encryptable<String>> e : encrypted.entrySet()) {
            plain.put(e.getKey(), e.getValue().decrypt(this.mapping).getData());
        }
        return plain;
    }

}
