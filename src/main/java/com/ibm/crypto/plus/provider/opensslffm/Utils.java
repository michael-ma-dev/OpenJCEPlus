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

    static OpenSSLException toOpenSSLException(String operation, Throwable t) {
        if (t instanceof OpenSSLException) {
            return (OpenSSLException) t;
        }
        return new OpenSSLException(operation + " failed: " + t.getMessage(), t);
    }

    private Utils() {}
}
