package com.kryptnostic.api.v1.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.RestAdapter;
import retrofit.RestAdapter.LogLevel;

import com.kryptnostic.api.v1.exceptions.DefaultErrorHandler;
import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.MetadataKeyService;
import com.kryptnostic.api.v1.indexing.metadata.Metadata;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.models.IndexableMetadata;
import com.kryptnostic.api.v1.models.request.DocumentRequest;
import com.kryptnostic.api.v1.models.request.MetadataRequest;
import com.kryptnostic.api.v1.models.response.ResponseKey;
import com.kryptnostic.api.v1.utils.JacksonConverter;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

// TODO: exception handling
public class DefaultKryptnosticConnection implements KryptnosticConnection {
    private static final Logger log = LoggerFactory.getLogger(KryptnosticConnection.class);
    private static final int TOKEN_LENGTH = 256;
    private static final int NONCE_LENGTH = 64;
    private static final int LOCATION_LENGTH = 64;
    private static final int BUCKET_SIZE = 100;

    private final KryptnosticStorage storageService;
    private final KryptnosticSearch searchService;
    private final MetadataKeyService keyService;
    private final IndexingService indexingService;

    public DefaultKryptnosticConnection(String url) {
        // initialize http
        RestAdapter restAdapter = new RestAdapter.Builder().setConverter(new JacksonConverter()).setEndpoint(url)
                .setErrorHandler(new DefaultErrorHandler()).setLogLevel(LogLevel.FULL).setLog(new RestAdapter.Log() {
                    @Override
                    public void log(String msg) {
                        log.debug(msg);
                    }
                }).build();
        storageService = restAdapter.create(KryptnosticStorage.class);
        searchService = restAdapter.create(KryptnosticSearch.class);
        // initialize indexing and metadata
        SimplePolynomialFunction indexingHashFunction = Indexes.generateRandomIndexingFunction(TOKEN_LENGTH,
                NONCE_LENGTH, LOCATION_LENGTH);
        keyService = new BalancedMetadataKeyService(indexingHashFunction, BUCKET_SIZE, NONCE_LENGTH);
        indexingService = new BaseIndexingService();
    }

    @Override
    public String uploadDocument(String document) throws BadRequestException {
        String id = storageService.uploadDocument(new DocumentRequest(document)).getData();

        // metadata stuff now
        // index + map tokens
        Set<Metadatum> metadata = indexingService.index(id, document);
        Metadata keyedMetadata = keyService.mapTokensToKeys(metadata);

        // format for metadata upload
        MetadataRequest req = new MetadataRequest();
        for (Map.Entry<String, List<Metadatum>> m : keyedMetadata.getMetadataMap().entrySet()) {
            log.debug("list" + m.getValue().toString());
            String key = m.getKey();
            String value = m.getValue().toString();
            req.addMetadata(new IndexableMetadata(key, value));
        }
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
