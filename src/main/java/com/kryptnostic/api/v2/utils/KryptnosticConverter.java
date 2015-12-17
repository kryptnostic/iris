package com.kryptnostic.api.v2.utils;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
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
import com.kryptnostic.kodex.v1.serialization.jackson.KodexObjectMapperFactory;

/**
 * A {@link Converter} that handles both json and byte arrays. Based off work by Kai Waldron
 * (kaiwaldron@gmail.com)
 * 
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class KryptnosticConverter implements Converter {
    private static final String JSON_MIME_TYPE = "application/json; charset=UTF-8";
    private static final String BYTE_MIME_TYPE = "application/octet-stream";
    private static final Logger logger         = LoggerFactory.getLogger( KryptnosticConverter.class );
    private final ObjectMapper  objectMapper;

    public KryptnosticConverter() {
        this.objectMapper = KodexObjectMapperFactory.getObjectMapper();
    }

    @Override
    public Object fromBody( TypedInput body, Type type ) throws ConversionException {
        try {
            if ( StringUtils.equals( body.mimeType(), BYTE_MIME_TYPE ) ) {
                return IOUtils.toByteArray( body.in() );
            }

            JavaType javaType = objectMapper.getTypeFactory().constructType( type );

            InputStream in = body.in();

            if ( in.available() == 0 ) {
                return null;
            }

            return objectMapper.readValue( body.in(), javaType );
        } catch ( IOException e ) {
            logger.error( "Unable to deserialize object of type {} from body with mime-type {}.",
                    type,
                    body.mimeType(),
                    e );
            throw new ConversionException( e );
        }
    }

    @Override
    public TypedOutput toBody( Object object ) {
        if ( byte[].class.isAssignableFrom( object.getClass() ) ) {
            return new TypedByteArray( BYTE_MIME_TYPE, (byte[]) object );
        }
        try {
            byte[] json = objectMapper.writeValueAsBytes( object );
            return new TypedByteArray( JSON_MIME_TYPE, json );// json.getBytes( "UTF-8" )
        } catch ( JsonProcessingException e ) {
            throw new AssertionError( e );
        } /*
           * catch ( UnsupportedEncodingException e ) { throw new AssertionError( e ); }
           */
    }
}