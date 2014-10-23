package com.kryptnostic.api.v1.client;

import java.io.File;
import java.io.IOException;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
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
    private static HashFunction hf = Hashing.murmur3_128();

    public FileStore(String name) {
        this.rootDirectory = new File(System.getProperty("user.home"), name);
        this.rootDirectory.mkdir();
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
        Long longEncodedKey = hf.hashBytes(key).asLong();
        return new File(rootDirectory, longEncodedKey.toString());
    }

}
