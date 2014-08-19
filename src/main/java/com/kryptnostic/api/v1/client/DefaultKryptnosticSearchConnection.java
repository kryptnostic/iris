package com.kryptnostic.api.v1.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

import retrofit.RestAdapter;
import retrofit.RestAdapter.Log;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.models.IndexableMetadata;
import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.ResponseKey;
import com.kryptnostic.indexing.BalancedMetadataKeyService;
import com.kryptnostic.indexing.BaseIndexingService;
import com.kryptnostic.indexing.Indexes;
import com.kryptnostic.indexing.IndexingService;
import com.kryptnostic.indexing.MetadataKeyService;
import com.kryptnostic.indexing.metadata.Metadata;
import com.kryptnostic.indexing.metadata.Metadatum;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

// TODO: exception handling
public class DefaultKryptnosticSearchConnection implements KryptnosticSearchConnection {
    final private KryptnosticSearch service;

    final private MetadataKeyService keyService;
    final private IndexingService indexingService;

    private static final int TOKEN_LENGTH = 256;
    private static final int NONCE_LENGTH = 64;
    private static final int LOCATION_LENGTH = 64;
    private static final int BUCKET_SIZE = 100;

    public DefaultKryptnosticSearchConnection(String url) {
        // initialize http
        RestAdapter restAdapter = new RestAdapter.Builder().setEndpoint(url).setErrorHandler(new DefaultErrorHandler())
                .setLogLevel(LogLevel.FULL).build();
        service = restAdapter.create(KryptnosticSearch.class);

        // initialize indexing and metadata
        SimplePolynomialFunction indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH,
                NONCE_LENGTH, LOCATION_LENGTH);
        keyService = new BalancedMetadataKeyService(indexingHashFunction, BUCKET_SIZE, NONCE_LENGTH);
        indexingService = new BaseIndexingService();
    }

    @Override
    public String uploadDocument(String document) {
        String id = service.uploadDocument(new DocumentRequest(document)).getData();

        // metadata stuff now
        // index + map tokens
        Set<Metadatum> metadata = indexingService.index(id, document);
        Metadata keyedMetadata = keyService.mapTokensToKeys(metadata);

        // format for metadata upload
        MetadataRequest req = new MetadataRequest();
        for (Map.Entry<String, List<Metadatum>> m : keyedMetadata.getMetadataMap().entrySet()) {
            System.out.println("list" + m.getValue().toString());
            req.addMetadata(new IndexableMetadata(m.getKey(), m.getValue().toString()));
        }
        service.uploadMetadata(req);

        System.out.println("generated metadata " + keyedMetadata);

        return id;
    }

    @Override
    public String updateDocument(String id, String document) {
        return service.updateDocument(id, new DocumentRequest(document)).getData();
    }

    @Override
    public String getDocument(String id) throws ResourceNotFoundException {
        return service.getDocument(id).getData().get(ResponseKey.DOCUMENT_KEY);
    }
}
