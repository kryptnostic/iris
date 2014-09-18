package com.kryptnostic.indexing;

import java.io.IOException;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.hash.Hashing;
import com.google.common.io.Resources;
import com.kryptnostic.api.v1.client.DefaultKryptnosticContext;
import com.kryptnostic.api.v1.indexing.BalancedMetadataKeyService;
import com.kryptnostic.api.v1.indexing.BaseIndexingService;
import com.kryptnostic.api.v1.security.InMemorySecurityService;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.MetadataKeyService;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadata;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.kodex.v1.security.SecurityService;
import com.kryptnostic.mock.services.MockNonceService;
import com.kryptnostic.mock.services.MockSearchFunctionService;
import com.kryptnostic.storage.v1.client.NonceApi;
import com.kryptnostic.storage.v1.client.SearchFunctionApi;

public class IndexingTests {
    private static final Logger logger = LoggerFactory.getLogger(IndexingTests.class);

    private static MetadataKeyService keyService;
    private static IndexingService indexingService;

    @BeforeClass
    public static void setupServices() {
        NonceApi nonceService = new MockNonceService();
        SecurityService securityService = new InMemorySecurityService();
        SearchFunctionApi searchFunctionService = new MockSearchFunctionService();
        KryptnosticContext context = new DefaultKryptnosticContext(searchFunctionService, nonceService, securityService);
        keyService = new BalancedMetadataKeyService(context);
        indexingService = new BaseIndexingService();
    }

    @Test
    public void testIndexingAndKeying() throws IOException {
        String document = Resources.toString(Resources.getResource("privacy.txt"), Charsets.UTF_8);
        logger.info("Loaded privacy.txt");
        long start = System.nanoTime();
        String documentId = Hashing.sha256().hashString(document, Charsets.UTF_8).toString();
        logger.info("Hashed document of length {} in {} ms.", document.length(),
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));

        start = System.nanoTime();
        Set<Metadatum> metadata = indexingService.index(documentId, document);
        logger.info("Indexed document of length {} in {} ms.", document.length(),
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
        Assert.assertNotNull(metadata);
        Assert.assertTrue(!metadata.isEmpty());

        start = System.nanoTime();
        Metadata balancedMetadata = keyService.mapTokensToKeys(metadata);
        logger.info("Mapped token keys in {} ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start));
        Assert.assertNotNull(balancedMetadata);
    }

}
