package com.kryptnostic.api.v1.client;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.kryptnostic.api.v1.exceptions.types.BadRequestException;
import com.kryptnostic.api.v1.exceptions.types.ResourceNotFoundException;
import com.kryptnostic.indexing.BalancedMetadataKeyService;
import com.kryptnostic.indexing.BaseIndexingService;
import com.kryptnostic.indexing.Indexes;
import com.kryptnostic.indexing.IndexingService;
import com.kryptnostic.indexing.MetadataKeyService;
import com.kryptnostic.indexing.metadata.Metadatum;
import com.kryptnostic.multivariate.gf2.SimplePolynomialFunction;

public class ClientTester {

    private static final String URL = "http://localhost:8081/rhizome/v1";

    public static void main(String[] args) throws ResourceNotFoundException, BadRequestException {
        DefaultKryptnosticSearchConnection conn = new DefaultKryptnosticSearchConnection(URL);

        String document = "I am so cool";
        
        String docid = conn.uploadDocument(document);
        
        System.out.println(conn.getDocument(docid));

    }
}
