package com.kryptnostic.api.v1.search;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.AsyncResult;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.client.SearchAPI;
import com.kryptnostic.api.v1.indexing.IndexingService;
import com.kryptnostic.api.v1.indexing.analysis.Analyzer;
import com.kryptnostic.api.v1.indexing.metadata.Metadatum;
import com.kryptnostic.api.v1.models.SearchResult;
import com.kryptnostic.api.v1.models.request.SearchRequest;

/**
 * Default implementation of SearchService. Must use same IndexingService as the KryptnosticConnection.
 * 
 * @author Nick Hewitt <nick@kryptnostic.com>
 *
 */
public class DefaultSearchService implements SearchService {
    private final SearchAPI searchService;
    private final IndexingService indexingService;
    private final DocumentSearcherFactory documentSearcherFactory;

    public DefaultSearchService(SearchAPI searchService, IndexingService indexingService) {
        this.searchService = searchService;
        this.indexingService = indexingService;
        this.documentSearcherFactory = new DefaultDocumentSearcherFactory(); // TODO get rid of this and refer to utility class.
    }

    /**
     * Analyze query into tokens, convert tokens into searchTokens, and generate a SearchRequest to Kryptnostic RESTful
     * search service.
     */
    @Override
    public Set<Metadatum> search(String query) {
        List<String> tokens = analyzeQuery(query);
        List<BitVector> searchTokens = getSearchTokens(tokens);

        List<Future<SearchResult>> futures = Lists.newArrayList();
        for (BitVector searchToken : searchTokens) {
            Future<SearchResult> future = executeSearch(searchToken);
            futures.add(future);
        }

        Set<Metadatum> results = Sets.newHashSet();
        for (int i = 0; i < searchTokens.size(); i++) {
            try {
                filterResults(results, futures.get(i).get());
            } catch (InterruptedException | ExecutionException e) {
                e.printStackTrace();
            }
        }

        return results;
    }

    /**
     * Add metadatum found to running Set of results.
     */
    private void filterResults(Set<Metadatum> results, SearchResult result) {
        // TODO Auto-generated method stub
    }

    /**
     * Asynchronous method to execute search via Kryptnostic RESTful service.
     * 
     * @return Future<SearchResult>
     */
    @Async
    private Future<SearchResult> executeSearch(BitVector searchToken) {
        SearchRequest request = SearchRequest.searchToken(searchToken);
        SearchResult result = searchService.search(request);
        return new AsyncResult<SearchResult>(result);
    }

    /**
     * @return List<BitVector> of search tokens, the ciphertext to be submitted to KryptnosticSearch.
     */
    private List<BitVector> getSearchTokens(List<String> tokens) {
        Preconditions.checkArgument(tokens != null, "Cannot pass null tokens param.");

        List<BitVector> searchTokens = Lists.newArrayList();
        for (String token : tokens) {
            BitVector searchToken = documentSearcherFactory.createSearchToken(token);
            searchTokens.add(searchToken);
        }
        return searchTokens;
    }

    /**
     * @return List<String> of unique tokens, the plaintext to be searched for in stored documents.
     */
    private List<String> analyzeQuery(String query) {
        Preconditions.checkArgument(query != null, "Cannot pass null query param.");

        Set<String> tokens = Sets.newHashSet();
        Set<Analyzer> analyzers = indexingService.getAnalyzers();
        for (Analyzer analyzer : analyzers) {
            Map<String, List<Integer>> analysis = analyzer.analyze(query);
            for (String token : analysis.keySet()) {
                tokens.add(token);
            }
        }
        return Lists.newArrayList(tokens);
    }

}
