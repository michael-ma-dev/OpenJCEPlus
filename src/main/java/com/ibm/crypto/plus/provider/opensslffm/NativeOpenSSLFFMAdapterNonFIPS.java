/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.opensslffm;

public class NativeOpenSSLFFMAdapterNonFIPS extends NativeOpenSSLFFMAdapter {
    private static volatile NativeOpenSSLFFMAdapterNonFIPS instance = null;

    private NativeOpenSSLFFMAdapterNonFIPS() {
        super(false);
    }

    public static NativeOpenSSLFFMAdapterNonFIPS getInstance() {
        if (instance == null) {
            synchronized (NativeOpenSSLFFMAdapterNonFIPS.class) {
                if (instance == null) {
                    instance = new NativeOpenSSLFFMAdapterNonFIPS();
                }
            }
        }

        return instance;
    }
}
