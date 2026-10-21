/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.opensslffm;

import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

final class StaticStub {

    // NOTE: These constants must match those defined in
    //       com.ibm.crypto.plus.provider.openssl.NativeOpenSSLFFMAdapter
    //
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_ID_OSSL_INSTALL_PATH = 1;
    private static final int VALUE_ID_OSSL_VERSION = 2;

    // Define macros in <openssl/crypto.h>
    //
    private static final int OPENSSL_VERSION_STRING = 6;     // "3.5.0"
    private static final int OPENSSL_INFO_CONFIG_DIR = 1001; // config directory

    // const char* OpenSSL_version(int type)
    private static final MethodHandle MH_OpenSSL_version =
            NativeOpenSSLFFMImplementation.downcall(
                    "OpenSSL_version",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    // const char* OPENSSL_info(int type)
    private static final MethodHandle MH_OPENSSL_info =
            NativeOpenSSLFFMImplementation.downcall(
                    "OPENSSL_info",
                    FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.JAVA_INT));

    static long initializeOSSL(boolean isFIPS) throws OpenSSLException {
        // Nothing to do. Method is a placeholder for future use.
        return 0;
    }

    static String CTX_getValue(long osslContextId, int valueId) throws OpenSSLException {
        try {
            MemorySegment result;
            switch (valueId) {
                case VALUE_ID_FIPS_APPROVED_MODE:
                    // Nothing to do.
                    return null;

                case VALUE_ID_OSSL_INSTALL_PATH:
                    result = (MemorySegment) MH_OPENSSL_info.invokeExact(OPENSSL_INFO_CONFIG_DIR);
                    break;

                case VALUE_ID_OSSL_VERSION:
                    result = (MemorySegment) MH_OpenSSL_version.invokeExact(OPENSSL_VERSION_STRING);
                    break;

                default:
                    throw new OpenSSLException("CTX_getValue: invalid valueId " + valueId);
            }

            if (result.equals(NativeOpenSSLFFMImplementation.NULL_PTR)) {
                throw new OpenSSLException("OPENSSL_info or OpenSSL_version failed");
            }
            return result.reinterpret(1024).getString(0);
        } catch (Throwable t) {
            throw Utils.toOpenSSLException("CTX_getValue", t);
        }
    }

    private StaticStub() {}
}
