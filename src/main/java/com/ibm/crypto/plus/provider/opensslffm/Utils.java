/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.opensslffm;

import com.ibm.crypto.plus.provider.openssl.OpenSSLException;

final class Utils {

    /**
     * Converts anything thrown while calling into OpenSSL into an
     * {@link OpenSSLException}. An {@code OpenSSLException} is returned
     * unchanged; any other throwable (for example from
     * {@code MethodHandle.invokeExact}) is wrapped.
     *
     * @param operation the name of the failing operation, for the message
     * @param t the throwable that was caught
     * @return the exception to throw
     */
    static OpenSSLException wrap(String operation, Throwable t) {
        if (t instanceof OpenSSLException) {
            return (OpenSSLException) t;
        }
        return new OpenSSLException(operation + " failed: " + t.getMessage(), t);
    }

    private Utils() {}
}
