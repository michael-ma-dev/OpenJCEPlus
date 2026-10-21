/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.opensslffm;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.security.ProviderException;
import sun.security.util.Debug;

final class NativeOpenSSLFFMImplementation {

    // User enabled debugging
    private static final Debug debug = Debug.getInstance("jceplus");

    private static final String OPENSSL_CORE_LIBRARY_NAME = "crypto";

    static final Linker LINKER = Linker.nativeLinker();
    static final MemorySegment NULL_PTR = MemorySegment.NULL;

    private static final SymbolLookup LIBCRYPTO = loadOSSLLibrary();

    static MethodHandle downcall(String name, FunctionDescriptor descriptor,
            Linker.Option... options) {
        MemorySegment symbol = LIBCRYPTO.find(name)
                .orElseThrow(() -> new ProviderException(
                        "Symbol not found in libcrypto: " + name));
        return LINKER.downcallHandle(symbol, descriptor, options);
    }

    static MemorySegment toSegment(long address) {
        return MemorySegment.ofAddress(address).reinterpret(1);
    }

    private static String getOSSLLibraryName() {
        String osName = System.getProperty("os.name");
        String osArch = System.getProperty("os.arch");

        String osslPath = System.getProperty("openssl.library.path");
        if (osslPath != null) {
            if (debug != null) {
                debug.println("Loading openssl library using value in property"
                        + " openssl.library.path: " + osslPath);
            }

            if (osName.equals("Mac OS X")) {
                return osslPath + "/lib" + OPENSSL_CORE_LIBRARY_NAME + ".dylib";
            } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
                return osslPath + "\\lib" + OPENSSL_CORE_LIBRARY_NAME + "-3-x64.dll";
            } else if (osName.equals("AIX")) {
                return osslPath + "/lib" + OPENSSL_CORE_LIBRARY_NAME + "64.so.3";
            } else {
                return osslPath + "/lib" + OPENSSL_CORE_LIBRARY_NAME + ".so";
            }
        }
        if (debug != null) {
            debug.println("Library path not found for openssl, use java home directory.");
        }

        String javaHome = System.getProperty("java.home");

        if (osName.startsWith("Windows")) {
            osslPath = javaHome + java.io.File.separator + "bin";
        } else {
            osslPath = javaHome + java.io.File.separator + "lib";
        }

        if (debug != null) {
            debug.println("Loading openssl library using value: " + osslPath);
        }

        if (osName.equals("Mac OS X")) {
            return osslPath + "/lib" + OPENSSL_CORE_LIBRARY_NAME + "-semeru.dylib";
        } else if (osName.startsWith("Windows") && osArch.equals("amd64")) {
            return osslPath + java.io.File.separator
                    + OPENSSL_CORE_LIBRARY_NAME + "-semeru.dll";
        } else {
            return osslPath + "/lib" + OPENSSL_CORE_LIBRARY_NAME + "-semeru.so";
        }
    }

    private static SymbolLookup loadOSSLLibrary() {
        String libPath = getOSSLLibraryName();
        try {
            SymbolLookup lookup = SymbolLookup.libraryLookup(libPath, Arena.global());
            if (debug != null) {
                debug.println("FFM backend loaded libcrypto from: " + libPath);
            }
            return lookup;
        } catch (IllegalArgumentException e) {
            throw new ProviderException(
                    "Could not load libcrypto for FFM backend from: " + libPath, e);
        }
    }

    private NativeOpenSSLFFMImplementation() {}
}
