package com.kryptnostic.api.v1.client;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.google.common.hash.HashFunction;
import com.google.common.hash.Hashing;
import com.kryptnostic.kodex.v1.storage.DataStore;

/**
 * A simple implementation of the client datastore. The keys are used to generate filenames.
 * 
 * @author Nick Hewitt &lt;nick@kryptnostic.com&gt;
 *
 */
public class FileStore implements DataStore {
    private final Path rootDirectory;
    private static HashFunction hf = Hashing.murmur3_128();

    public FileStore(String name) {
        this.rootDirectory = Paths.get(System.getProperty("user.home"), name);
        File dir = rootDirectory.toFile();
        dir.mkdir();
    }

    @Override
    public byte[] get(byte[] key) throws IOException {
        Path keyPath = keyToPath(key);
        try {
            byte[] data = Files.readAllBytes(keyPath);
            return data;
        } catch (NoSuchFileException e) {
            return null;
        }
    }

    @Override
    public void put(byte[] key, byte[] value) throws IOException {
        Path keyPath;
        keyPath = keyToPath(key);
        Files.write(keyPath, value);
    }

    private Path keyToPath(byte[] key) {
        Long longEncodedKey = hf.hashBytes(key).asLong();
        return rootDirectory.resolve(longEncodedKey.toString());
    }

}
