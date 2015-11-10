package com.kryptnostic.api.v1.search;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.search.v1.http.SearchApi;
import com.kryptnostic.search.v1.models.request.SearchRequest;
import com.kryptnostic.search.v1.models.response.SearchResultResponse;

/**
 * Default implementation of SearchService. Must use same IndexingService as the KryptnosticConnection.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class DefaultSearchClient implements SearchClient {
    private final SearchApi             searchApi;
    private final Indexer               indexer;
    private final KryptnosticConnection connection;

    public DefaultSearchClient( KryptnosticConnection connection ) {
        this.connection = connection;
        this.searchApi = connection.getSearchApi();
        this.indexer = new SimpleIndexer();
    }

    /**
     * Analyze query into tokens, convert tokens into searchTokens, and generate a SearchRequest to Kryptnostic RESTful
     * search service.
     */

    @Override
    public SearchResultResponse search( String query ) {
        return search( query, null );
    }

    @Override
    public SearchResultResponse search( String query, SearchRequest request ) {
        List<String> tokens = analyzeQuery( query );
        SearchRequest searchRequest = generateSearchRequest( tokens );

        if ( request != null ) {
            searchRequest = new SearchRequest(
                    searchRequest.getSearchToken(),
                    request.getMaxResults(),
                    request.getOffset() );
        }

        return search( searchRequest );
    }

    @Override
    public SearchResultResponse search( SearchRequest request ) {
        return searchApi.search( request );
    }

    /**
     * @return SearchRequest based on search tokens, the ciphertext to be submitted to KryptnosticSearch.
     */
    @Override
    public SearchRequest generateSearchRequest( List<String> tokens ) {
        Preconditions.checkArgument( tokens != null, "Cannot pass null tokens param." );

        List<byte[]> searchTokens = Lists.newArrayList();
        for ( String token : tokens ) {
            searchTokens.add( connection.newCryptoManager().prepareSearchToken( token ) );
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
