package com.kryptnostic.api.v1.search;

import java.util.List;
import java.util.Map;
import java.util.Set;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.Indexes;
import com.kryptnostic.kodex.v1.indexing.IndexingService;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.kodex.v1.indexing.metadata.Metadatum;
import com.kryptnostic.search.v1.SearchService;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.search.v1.models.request.SearchRequest;
import com.kryptnostic.search.v1.models.response.SearchResultResponse;

/**
 * Default implementation of SearchService. Must use same IndexingService as the KryptnosticConnection.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class DefaultSearchService implements SearchService {
    private final SearchApi searchService;
    private final IndexingService indexingService;

    public DefaultSearchService(SearchApi searchService, IndexingService indexingService) {
        this.searchService = searchService;
        this.indexingService = indexingService;
    }

    /**
     * Analyze query into tokens, convert tokens into searchTokens, and generate a SearchRequest to Kryptnostic RESTful
     * search service.
     */
    @Override
    public Set<Metadatum> search(String query) {
        List<String> tokens = analyzeQuery(query);
        List<SearchRequest> searchRequests = generateSearchRequests(tokens);
        
        SearchResultResponse searchResult = searchService.search(searchRequests);
        
        throw new UnsupportedOperationException("Search result parsing not implemented yet");
    }

    /**
     * @return List<BitVector> of search tokens, the ciphertext to be submitted to KryptnosticSearch.
     */
    private List<SearchRequest> generateSearchRequests(List<String> tokens) {
        Preconditions.checkArgument(tokens != null, "Cannot pass null tokens param.");

        List<SearchRequest> searchRequests = Lists.newArrayList();
        for (String token : tokens) {
            BitVector searchToken = Indexes.computeHashAndGetBits(token);
            SearchRequest searchRequest = SearchRequest.searchToken(searchToken);
            searchRequests.add(searchRequest);
        }
        return searchRequests;
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
