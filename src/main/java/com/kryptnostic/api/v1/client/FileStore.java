package com.kryptnostic.api.v1.client;

import java.io.File;
import java.io.IOException;

import com.google.common.io.Files;
import com.kryptnostic.kodex.v1.storage.DataStore;

/**
 * A simple implementation of the client datastore. The keys are used to generate filenames.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class FileStore implements DataStore {
    private final File rootDirectory;

    public FileStore( String name ) {
        this.rootDirectory = new File( ".kryptnostic", name );
        this.rootDirectory.mkdirs();
    }

    @Override
    public byte[] get( String dir, String file ) throws IOException {
        File keyFile = keyToFile( dir, file );
        if ( keyFile.isFile() ) {
            byte[] data = Files.toByteArray( keyFile );
            return data;
        }
        return null;
    }

    @Override
    public void put( String dir, String file, byte[] value ) throws IOException {
        File keyFile = keyToFile( dir, file );
        Files.write( value, keyFile );
    }

    private File keyToFile( String dir, String file ) {
        file = clean( file );
        if ( dir != null ) {
            file = clean( dir ) + File.pathSeparator + file;
        }
        return new File( rootDirectory, file );
    }

    @Override
    public byte[] get( String file ) throws IOException {
        return get( null, file );
    }

    @Override
    public void put( String file, byte[] value ) throws IOException {
        put( null, file, value );
    }

    private String clean( String str ) {
        return str.replaceAll( "[^\\w\\.]+", "" );
    }
}
