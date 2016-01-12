package com.kryptnostic.api.v1.search;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.indexing.SimpleIndexer;
import com.kryptnostic.kodex.v1.crypto.ciphers.AesCryptoService;
import com.kryptnostic.kodex.v1.indexing.Indexer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.v2.search.SearchApi;
import com.kryptnostic.v2.search.SearchResult;
import com.kryptnostic.v2.search.SearchResultResponse;

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
    public Set<SearchResult> submitTermQuery( Map<String, byte[]> query ) {
        return searchApi.submitTermQuery( query );
    }

    /**
     * @return SearchRequest based on search tokens, the ciphertext to be submitted to KryptnosticSearch.
     */
    @Override
    public Map<String, byte[]> buildTermQuery( List<String> searchTerms ) {
        Preconditions.checkArgument( searchTerms != null, "Cannot pass null tokens param." );

        Iterable<String> analyzedTerms = Iterables
                .concat( Lists.transform( searchTerms, new Function<String, List<String>>() {

                    @Override
                    public List<String> apply( String searchTerm ) {
                        return analyzeQuery( searchTerm );
                    }
                } ) );

        for( String analyzedTerm : analyzedTerms ) {
            
        }
        Iterable<byte[]> fheEncryptedSearchTerms = Iterables.transform( analyzedTerms, new Function<String, byte[]>() {

            @Override
            public byte[] apply( String searchTerm ) {
                return connection.newCryptoManager().prepareSearchToken( searchTerm );
            }

        } );
        AesCryptoService cryptoService = connection.getMasterCryptoService();
        
        cryptoService.getSecretKey()
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
