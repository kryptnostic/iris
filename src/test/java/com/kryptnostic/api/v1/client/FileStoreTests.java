package com.kryptnostic.api.v1.client;

import com.kryptnostic.utils.DataStoreTestsBase;

public class FileStoreTests extends DataStoreTestsBase {
    static {
        store = new FileStore( "iris-tests" );
    }
}
