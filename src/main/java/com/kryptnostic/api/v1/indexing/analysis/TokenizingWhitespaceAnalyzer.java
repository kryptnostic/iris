package com.kryptnostic.api.v1.indexing.analysis;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Maps;
import com.kryptnostic.kodex.v1.indexing.QueryAnalyzer;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;

/**
 * Basic tokenizer that uses a regular expression to parse a source string.
 * 
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 */
public class TokenizingWhitespaceAnalyzer implements Analyzer, QueryAnalyzer {
    private static final Pattern onlyWords = Pattern.compile( "([a-zA-Z0-9]+)" );
    private final int            bucketSize;

    public TokenizingWhitespaceAnalyzer( int bucketSize ) {
        this.bucketSize = bucketSize;
    }

    // TODO: Make a generic analyzer that takes in a pattern and indexes on resulting tokens.
    public Map<String, List<List<Integer>>> analyze( String source ) {
        Matcher m = onlyWords.matcher( source );
        Map<String, List<List<Integer>>> hits = Maps.newHashMap();
        while ( m.find() ) {
            int location = m.start();
            String s = m.group().toLowerCase();
            List<List<Integer>> locations = hits.get( s );
            if ( locations == null ) {
                locations = new ArrayList<>();
                locations.add( new ArrayList<Integer>( bucketSize ) );
                hits.put( s, locations );
            } else if ( locations.get( locations.size() - 1 ).size() == bucketSize ) {
                locations.add( new ArrayList<Integer>( bucketSize ) );
            }
            
            locations.get( locations.size() - 1 ).add( location );
        }

        return hits;
    }

    @Override
    public Set<String> analyzeQuery( String query ) {
        return ImmutableSet.copyOf( analyze( query ).keySet() );
    }
}
