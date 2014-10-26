package com.kryptnostic.api.v1.search;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import cern.colt.bitvector.BitVector;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.kodex.v1.client.KryptnosticContext;
import com.kryptnostic.kodex.v1.exceptions.types.IrisException;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.search.v1.client.SearchApi;
import com.kryptnostic.search.v1.models.SearchResult;
import com.kryptnostic.search.v1.models.request.SearchRequest;
import com.kryptnostic.search.v1.models.response.SearchResultResponse;

/**
 * Default implementation of SearchService. Must use same IndexingService as the KryptnosticConnection.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class DefaultSearchClient implements SearchClient {
    private final SearchApi          searchService;
    private final Indexer            indexer;
    private final KryptnosticContext context;

    public DefaultSearchClient( KryptnosticContext context, SearchApi searchService ) {
        this.context = context;
        this.searchService = searchService;
        this.indexer = new SimpleIndexer( context.getSecurityService().getUserKey() );
    }

    /**
     * Analyze query into tokens, convert tokens into searchTokens, and generate a SearchRequest to Kryptnostic RESTful
     * search service.
     * 
     * @throws IrisException
     */
    @Override
    public Collection<SearchResult> search( String query ) {
        List<String> tokens = analyzeQuery( query );
        SearchRequest searchRequest = generateSearchRequest( tokens );

        SearchResultResponse searchResult = searchService.search( searchRequest );

        return searchResult.getData();
    }

    /**
     * @return List<BitVector> of search tokens, the ciphertext to be submitted to KryptnosticSearch.
     * @throws IrisException
     */
    private SearchRequest generateSearchRequest( List<String> tokens ) {
        Preconditions.checkArgument( tokens != null, "Cannot pass null tokens param." );

        Collection<BitVector> searchTokens = Lists.newArrayList();
        for ( String token : tokens ) {
            searchTokens.add( context.prepareSearchToken( token ) );
        }

        return SearchRequest.searchToken( searchTokens );
    }

    /**
     * @return List<String> of unique tokens, the plaintext to be searched for in stored documents.
     */
    private List<String> analyzeQuery( String query ) {
        Preconditions.checkArgument( query != null, "Cannot pass null query param." );

        Set<String> tokens = Sets.newHashSet();
        Set<Analyzer> analyzers = indexer.getAnalyzers();
        for ( Analyzer analyzer : analyzers ) {
            Map<String, List<Integer>> analysis = analyzer.analyze( query );
            for ( String token : analysis.keySet() ) {
                tokens.add( token );
            }
        }
        return Lists.newArrayList( tokens );
    }

}
