package com.kryptnostic.api.v1.sharing;

import com.kryptnostic.krypto.engine.KryptnosticEngine;

public final class IndexPair {
    private IndexPair( byte[] objectSearchKey, byte[] objectAddressMatrix ) {
        this.objectSearchKey = objectSearchKey;
        this.objectAddressMatrix = objectAddressMatrix;
    }

    private final byte[] objectSearchKey;
    private final byte[] objectAddressMatrix;

    public static IndexPair newFromKryptnosticEngine( KryptnosticEngine engine ) {
        return new IndexPair( engine.getObjectSearchKey(), engine.getObjectAddressMatrix() );
    }

    public byte[] getObjectSearchKey() {
        return objectSearchKey;
    }

    public byte[] getObjectAddressMatrix() {
        return objectAddressMatrix;
    }

    public byte[] computeIndexPair( KryptnosticEngine engine ) {
        return engine.getObjectIndexPair( objectSearchKey, objectAddressMatrix );
    }

    public byte[] computeSharingPair( KryptnosticEngine engine ) {
        return engine.getObjectSharingPair( engine.getObjectIndexPair( objectSearchKey, objectAddressMatrix ) );
    }
}
