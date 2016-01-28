package com.kryptnostic.api.v1.search;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.kryptnostic.api.v1.KryptnosticConnection;
import com.kryptnostic.api.v1.KryptnosticCryptoManager;
import com.kryptnostic.api.v1.indexing.analysis.PatternMatchingAnalyzer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;
import com.kryptnostic.search.v1.SearchClient;
import com.kryptnostic.v2.search.SearchApi;

/**
 * Default implementation of SearchService. Must use same Indexer as the KryptnosticConnection.
 *
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class DefaultSearchClient implements SearchClient {

    private static final Analyzer DEFAULT_ANALYZER = new PatternMatchingAnalyzer();

    private final KryptnosticCryptoManager cryptoManager;
    private final SearchApi searchApi;
    private final Analyzer analyzer;

    public DefaultSearchClient(
            KryptnosticConnection connection,
            Analyzer analyzer ) {
        this.cryptoManager = connection.newCryptoManager();
        this.searchApi = connection.getSearchApi();
        this.analyzer = analyzer;

    }

    public DefaultSearchClient( KryptnosticConnection connection ) {
        this( connection, DEFAULT_ANALYZER );
    }

    // TODO (elliott): Actually return the InvertedIndexSegments instead?

    @Override
    public Set<UUID> search( List<String> terms ) {
        Preconditions.checkNotNull( terms );
        Set<byte[]> fheEncryptedSearchTerms = Sets.newHashSet();
        for (String term : terms) {
            for (String token : analyzer.tokenize( term )) {
                fheEncryptedSearchTerms.add( fheEncryptSearchTerm( token ) );
            }
        }
        return searchApi.search( fheEncryptedSearchTerms );
    }

    @Override
    public Set<UUID> search( String... terms ) {
        return search( Lists.newArrayList( terms ) );
    }

    private byte[] fheEncryptSearchTerm( String processedSearchTerm ) {
        // TODO (elliott): Is it safe to reuse the same KryptnosticCryptoManager instance?
        return cryptoManager.prepareSearchToken( processedSearchTerm );
    }

}
