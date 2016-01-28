package com.kryptnostic.api.v1.indexing.analysis;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.kryptnostic.kodex.v1.indexing.analysis.Analyzer;

import jdk.nashorn.internal.parser.Token;

/**
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 */
public class PatternMatchingAnalyzer implements Analyzer {

    private static final int DEFAULT_MINIMUM_TOKEN_LENGTH = 2;
    private static final Pattern DEFAULT_PATTERN = Pattern.compile( "([a-zA-Z0-9]+)" );
    private static final Function<String, String> DEFAULT_CANONICALIZER =
            new Function<String, String>() {
                @Override
                public String apply( String input ) {
                    return input.toLowerCase();
                }
            };
    private static final Set<String> DEFAULT_STOPWORDS = ImmutableSet.of();

    private final int minimumTokenLength;
    private final Pattern pattern;
    private final Function<String, String> canonicalizer;
    private final Set<String> stopwords;

    public PatternMatchingAnalyzer(
            int minimumTokenLength,
            Pattern pattern,
            Function<String, String> canonicalizer,
            Set<String> stopwords ) {
        this.minimumTokenLength = minimumTokenLength;
        this.pattern = pattern;
        this.canonicalizer = canonicalizer;
        this.stopwords = stopwords;
    }

    public PatternMatchingAnalyzer() {
        this(
                DEFAULT_MINIMUM_TOKEN_LENGTH,
                DEFAULT_PATTERN,
                DEFAULT_CANONICALIZER,
                DEFAULT_STOPWORDS );
    }

    @Override
    public Map<String, List<Integer>> buildInvertedIndex( String contents ) {
        Matcher matcher = pattern.matcher( contents );
        Map<String, List<Integer>> invertedIndex = Maps.newHashMap();
        while (matcher.find()) {
            int location = matcher.start();
            String token = canonicalizer.apply( matcher.group() );
            if ( shouldIncludeToken( token ) ) {
                if (!invertedIndex.containsKey( token )) {
                    invertedIndex.put( token, Lists.newArrayList( location ) );
                } else {
                    invertedIndex.get( token ).add( location );
                }
            }
        }
        return invertedIndex;
    }

    @Override
    public Set<String> tokenize( String contents ) {
        Matcher matcher = pattern.matcher( contents );
        Set<String> tokens = Sets.newHashSet();
        while (matcher.find()) {
            String token = canonicalizer.apply( matcher.group() );
            if ( shouldIncludeToken( token ) ) {
                tokens.add( canonicalizer.apply( matcher.group()) );
            }
        }
        return tokens;
    }

    private boolean shouldIncludeToken( String token ) {
        return token.length() >= minimumTokenLength && !stopwords.contains( token );
    }

}
