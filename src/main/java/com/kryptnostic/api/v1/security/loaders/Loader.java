package com.kryptnostic.api.v1.security.loaders;

import com.kryptnostic.kodex.v1.exceptions.types.KodexException;

/**
 * Generic way to represent a validation-enforcing loading of data
 * 
 * Useful as a collection of loaders to try sequentially
 * 
 * @author sinaiman
 *
 * @param <T> Type you are loading
 */
public abstract class Loader<T> {
    protected abstract T tryLoading() throws KodexException;

    protected abstract boolean validate( T keys ) throws KodexException;

    public abstract T load() throws KodexException;

}
