package com.kryptnostic.api.v1.utils;

import java.util.Map.Entry;

public class DocumentFragmentFormatter {

    /**
     * Assumes item.offset maps to beginning of a word in item.getValue and that word only occurs once in item.getValue
     * 
     * @param item
     * @param wordWindow
     * @return
     */
    public static String format( Entry<Integer, String> item, int wordWindow ) {
        int offset = item.getKey();
        String block = item.getValue();

        block = block.replaceAll( "\\n", " " );

        if ( offset > block.length() ) {
            throw new IllegalArgumentException( "Offset (" + offset + ") is greater than block length ("
                    + block.length() + "), which is invalid when formatting a document fragment" );
        }
        if ( offset < 0 ) {
            throw new IllegalArgumentException( "Offset (" + offset
                    + ") is negative, which is invalid when formatting a document fragment" );
        }
        if ( wordWindow < 0 ) {
            throw new IllegalArgumentException( "Character window (" + wordWindow
                    + ") is negative, which is invalid when formatting a document fragment" );
        }

        int endOfWord = block.indexOf( ' ', offset );
        if ( endOfWord < 0 ) {
            endOfWord = block.length();
        }

        String token = block.substring( offset, endOfWord );

        String[] blockSplit = block.split( "[\\s]" );

        String result = "";

        int targetIndex = -1;
        for ( int i = 0; i < blockSplit.length; i++ ) {
            if ( blockSplit[ i ].equals( token ) ) {
                targetIndex = i;
                break;
            }
        }
        int startIndex = targetIndex - wordWindow;
        if ( startIndex < 0 ) {
            startIndex = 0;
        }
        int endIndex = targetIndex + wordWindow + 1;
        if ( endIndex > blockSplit.length ) {
            endIndex = blockSplit.length;
        }
        for ( int i = startIndex; i < endIndex; i++ ) {
            result += blockSplit[ i ];
            if ( i < endIndex - 1 ) {
                result += " ";
            }
        }

        return result;
    }

}
