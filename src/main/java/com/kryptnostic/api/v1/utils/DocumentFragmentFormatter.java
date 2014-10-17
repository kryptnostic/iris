package com.kryptnostic.api.v1.utils;

import java.util.Map.Entry;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DocumentFragmentFormatter {

    /**
     * Assumes item.offset maps to beginning of a word in item.getValue and that word only occurs once in item.getValue
     * @param item
     * @param wordWindow
     * @return
     */
    public static String format(Entry<Integer, String> item, int wordWindow) {
        int offset = item.getKey();
        String block = item.getValue();
        
        if (offset < 0 || offset > block.length() || wordWindow < 0) {
            throw new IllegalArgumentException();
        }
        
        int endOfWord = block.indexOf(' ', offset);
        if (endOfWord < 0) {
            endOfWord = block.length();
        }
        
        String token = block.substring(offset, endOfWord);
        
        String pattern = token;
        
        boolean hasBeginning = false;
        boolean hasEnd = false;
        if (offset > 0) {
            hasBeginning = true;
            pattern = "((\\w+\\W*){0," + wordWindow + "})\\W" + pattern;
        }
        if (endOfWord < block.length()) {
            hasEnd = true;
            pattern += "\\W((\\W*\\w+){0," + wordWindow + "})";
        }
        
        Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
        
        Matcher m = p.matcher(block);
        m.find();
        m.groupCount();
        
        String result = "";
        
        if (hasBeginning) {
            String beginning = m.group(1);
            if (beginning != null && beginning.length() > 0) {
                result += beginning + " ";
            }
        }
        
        result += token;
        
        if (hasEnd) {
            int endIndex = 3;
            if (!hasBeginning) {
                endIndex = 1;
            }
            String end = m.group(endIndex);
            if (end != null && end.length() > 0) {
                result += " " + end;
            }
        }
        
        return result;
    }

    
}
