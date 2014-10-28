package com.kryptnostic.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.junit.Before;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

public class BaseSerializationTest {

    protected ObjectMapper mapper;

    @Before
    public final void init() {
        mapper = KodexObjectMapperFactory.getObjectMapper();
    }

    protected String wrapQuotes( String m ) {
        return "\"" + m + "\"";
    }

    protected <T> String serialize( T val ) throws JsonGenerationException, JsonMappingException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        mapper.writeValue( out, val );
        return out.toString();
    }

    @SuppressWarnings( "unchecked" )
    protected <T> T deserialize( String in, @SuppressWarnings( "rawtypes" ) Class type ) throws JsonParseException,
            JsonMappingException, IOException {
        return (T) mapper.readValue( in, type );
    }

    @SuppressWarnings( "unchecked" )
    protected <T> T deserialize( String in, @SuppressWarnings( "rawtypes" ) TypeReference type )
            throws JsonParseException, JsonMappingException, IOException {
        return (T) mapper.readValue( in, type );
    }

    @SuppressWarnings( "unchecked" )
    protected <T> T deserialize( String in, JavaType type ) throws JsonParseException, JsonMappingException,
            IOException {
        return (T) mapper.readValue( in, type );
    }
}
