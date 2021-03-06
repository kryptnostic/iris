package com.kryptnostic.api.v1.utils;

import java.io.IOException;
import java.lang.reflect.Type;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import retrofit.converter.ConversionException;
import retrofit.converter.Converter;
import retrofit.mime.TypedByteArray;
import retrofit.mime.TypedInput;
import retrofit.mime.TypedOutput;

/**
 * Retrofit converter for byte arrays.
 * 
 * @author Matthew Tamayo-Rios &lt;matthew@kryptnostic.com&gt;
 *
 */
public class ByteArrayConverter implements Converter {
    private static final String MIME_TYPE = "application/octet-stream";
    private static final Logger logger    = LoggerFactory.getLogger( ByteArrayConverter.class );

    @Override
    public Object fromBody( TypedInput body, Type type ) throws ConversionException {
        byte[] readbuf;
        try {
            readbuf = IOUtils.toByteArray( body.in() );
            return readbuf;
        } catch ( IOException e ) {
            logger.error( "Unable to deserialize object of type {}", type );
            throw new ConversionException( e );
        }
    }

    @Override
    public TypedOutput toBody( Object object ) {
        if ( object instanceof byte[] ) {
            byte[] body = (byte[]) object;
            return new TypedByteArray( MIME_TYPE, body );
        } else {
            throw new UnsupportedOperationException( "Byte Array Converter cannot handle objects of type: "
                    + object.getClass().getCanonicalName() );
        }
    }
}