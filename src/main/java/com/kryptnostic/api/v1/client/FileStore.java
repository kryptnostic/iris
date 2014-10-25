package com.kryptnostic.api.v1.client;

import java.io.File;
import java.io.IOException;

import org.apache.commons.codec.binary.Hex;

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

    public FileStore(String name) {
        this.rootDirectory = new File("kryptnostic", name);
        this.rootDirectory.mkdirs();
    }

    @Override
    public byte[] get(byte[] key) throws IOException {
        File keyFile = keyToFile(key);
        if (keyFile.isFile()) {
            byte[] data = Files.toByteArray(keyFile);
            return data;
        }
        return null;
    }

    @Override
    public void put(byte[] key, byte[] value) throws IOException {
        File keyFile = keyToFile(key);
        Files.write(value, keyFile);
    }

    private File keyToFile(byte[] key) {
        return new File(rootDirectory, Hex.encodeHexString( key ) );
    }
}
