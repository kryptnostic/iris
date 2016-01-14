package com.kryptnostic.api.v1.search;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.base.Function;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.search.SearchResult;

/**
 * Default implementation of SearchService. Must use same IndexingService as the KryptnosticConnection.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
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

    @Override
    public Set<SearchResult> search( List<String> searchTerms ) {
        return submitTermQuery( buildTermQuery( searchTerms ) );
    }

    /**
     * Analyze query into tokens, convert tokens into searchTokens, and generate a SearchRequest to Kryptnostic RESTful
     * search service.
     */

    @Override
    public Set<SearchResult> search( String... searchTerms ) {
        return search( Arrays.asList( searchTerms ) );
    }

    @Override
    public Set<SearchResult> submitTermQuery( Map<byte[], byte[]> query ) {
        return searchApi.submitTermQuery( query );
    }

    /**
     * @return SearchRequest based on search tokens, the ciphertext to be submitted to KryptnosticSearch.
     */
    @Override
    public Map<byte[], byte[]> buildTermQuery( List<String> searchTerms ) {

        Preconditions.checkArgument( searchTerms != null, "Cannot pass null tokens param." );

        Iterable<String> analyzedTerms = Iterables
                .concat( Lists.transform( searchTerms, new Function<String, Iterable<String>>() {

                    @Override
                    public Iterable<String> apply( String searchTerm ) {
                        return analyzeQuery( searchTerm );
                    }
                } ) );

        Map<byte[], byte[]> termQuery = Maps.newHashMap();
        KryptnosticCryptoManager crypto = connection.newCryptoManager();

        for ( String analyzedTerm : analyzedTerms ) {
            termQuery.put( crypto.computeSearchToken( analyzedTerm ), crypto.prepareSearchToken( analyzedTerm ) );
        }

        return termQuery;
    }

    /**
     * @return List<String> of unique tokens, the plaintext to be searched for in stored documents.
     */
    private Iterable<String> analyzeQuery( final String query ) {
        Preconditions.checkArgument( query != null, "Cannot pass null query param." );

        return Iterables.concat( Iterables.transform( indexer.getAnalyzers(), new Function<Analyzer, Set<String>>() {

            @Override
            public Set<String> apply( Analyzer input ) {
                return input.analyze( query ).keySet();
            }
        } ) );
    }

}
