package com.kryptnostic.api.v1.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.converter.ConversionException;
import retrofit.converter.Converter;
import retrofit.mime.TypedByteArray;
import retrofit.mime.TypedInput;
import retrofit.mime.TypedOutput;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kryptnostic.kodex.v1.crypto.keys.CryptoServiceLoader;
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

/**
 * A {@link Converter} which uses Jackson for reading and writing entities.
 *
 * @author Kai Waldron (kaiwaldron@gmail.com)
 */
public class JacksonConverter implements Converter {
    private static final String MIME_TYPE = "application/json; charset=UTF-8";
    private static final Logger logger = LoggerFactory.getLogger( JacksonConverter.class );
    private final ObjectMapper  objectMapper;

    public JacksonConverter() {
        this.objectMapper = KodexObjectMapperFactory.getObjectMapper();
    }
    
    public JacksonConverter( CryptoServiceLoader securityConfig ) {
        this.objectMapper = KodexObjectMapperFactory.getObjectMapper( securityConfig );
    }

    @Override
    public Object fromBody( TypedInput body, Type type ) throws ConversionException {
        try {
            JavaType javaType = objectMapper.getTypeFactory().constructType( type );
            InputStream in = body.in();
            if ( in.available() == 0 ) {
                return null;
            }
            return objectMapper.readValue( body.in(), javaType );
        } catch ( IOException e ) {
            logger.error( "Unable to deserialize object of type {}", type );
            try {
                logger.error("Representation: {}" , IOUtils.toString( body.in() ) );
            } catch ( IOException e1 ) {
                throw new ConversionException( e1 );
            }
            throw new ConversionException( e );
        }
    }

    @Override
    public TypedOutput toBody( Object object ) {
        try {
            String json = objectMapper.writeValueAsString( object );
            return new TypedByteArray( MIME_TYPE, json.getBytes( "UTF-8" ) );
        } catch ( JsonProcessingException e ) {
            throw new AssertionError( e );
        } catch ( UnsupportedEncodingException e ) {
            throw new AssertionError( e );
        }
    }
}