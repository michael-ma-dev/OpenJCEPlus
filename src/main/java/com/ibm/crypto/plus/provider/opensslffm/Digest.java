/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.opensslffm;

import com.ibm.crypto.plus.provider.openssl.OpenSSLException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;

/**
 * FFM implementation of the message digest functions that the JNI backend
 * provides in {@code Digest.c}.
 */
final class Digest {

    private static final MemorySegment NULL_PTR = NativeOpenSSLFFMImplementation.NULL_PTR;

    // EVP_MD_CTX* EVP_MD_CTX_new(void)
    private static final MethodHandle MH_EVP_MD_CTX_new =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_CTX_new",
                    FunctionDescriptor.of(ValueLayout.ADDRESS));

    // void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
    private static final MethodHandle MH_EVP_MD_CTX_free =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_CTX_free",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    // int EVP_MD_CTX_copy(EVP_MD_CTX *out, const EVP_MD_CTX *in)
    private static final MethodHandle MH_EVP_MD_CTX_copy =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_CTX_copy",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    // EVP_MD* EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties)
    private static final MethodHandle MH_EVP_MD_fetch =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_fetch",
                    FunctionDescriptor.of(ValueLayout.ADDRESS,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    // void EVP_MD_free(EVP_MD *md)
    private static final MethodHandle MH_EVP_MD_free =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_free",
                    FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    // int EVP_DigestInit_ex2(EVP_MD_CTX *ctx, const EVP_MD *type, const OSSL_PARAM params[])
    private static final MethodHandle MH_EVP_DigestInit_ex2 =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_DigestInit_ex2",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));

    // int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
    private static final MethodHandle MH_EVP_DigestUpdate =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_DigestUpdate",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG),
                    Linker.Option.critical(true));

    // int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s)
    private static final MethodHandle MH_EVP_DigestFinal_ex =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_DigestFinal_ex",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT,
                            ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS),
                    Linker.Option.critical(true));

    // int EVP_MD_CTX_get_size_ex(const EVP_MD_CTX *ctx)
    // EVP_MD_CTX_get_size is only a macro alias for this function, so it is not an
    // exported symbol and cannot be looked up directly.
    private static final MethodHandle MH_EVP_MD_CTX_get_size_ex =
            NativeOpenSSLFFMImplementation.downcall(
                    "EVP_MD_CTX_get_size_ex",
                    FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS));


    static long DIGEST_create(String digestAlgo) throws OpenSSLException {
        if (digestAlgo == null) {
            throw new OpenSSLException("DIGEST_create: The specified digest algorithm is null");
        }

        MemorySegment md = NULL_PTR;
        MemorySegment mdCtx = NULL_PTR;
        long digestId = 0;

        try (Arena arena = Arena.ofConfined()) {
            MemorySegment digestAlgoChars = arena.allocateFrom(digestAlgo);

            md = (MemorySegment) MH_EVP_MD_fetch.invokeExact(NULL_PTR, digestAlgoChars, NULL_PTR);
            if (md.equals(NULL_PTR)) {
                throw new OpenSSLException("DIGEST_create: EVP_MD_fetch failed");
            }

            mdCtx = (MemorySegment) MH_EVP_MD_CTX_new.invokeExact();
            if (mdCtx.equals(NULL_PTR)) {
                throw new OpenSSLException("DIGEST_create: EVP_MD_CTX_new failed");
            }

            int rc = (int) MH_EVP_DigestInit_ex2.invokeExact(mdCtx, md, NULL_PTR);
            if (rc != 1) {
                throw new OpenSSLException("DIGEST_create: EVP_DigestInit_ex2 failed");
            }

            // Everything succeeded. Set digestId to the created EVP_MD_CTX.
            digestId = mdCtx.address();
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_create", t);
        } finally {
            // EVP_DigestInit_ex2 takes its own reference to md (stored in mdCtx), so the
            // reference from EVP_MD_fetch must always be released here, on success or
            // failure, to avoid a refcount leak. EVP_MD_free(NULL) is a no-op.
            // On failure the half-built context is freed as well.
            //
            try {
                MH_EVP_MD_free.invokeExact(md);
                if (digestId == 0 && !mdCtx.equals(NULL_PTR)) {
                    MH_EVP_MD_CTX_free.invokeExact(mdCtx);
                }
            } catch (Throwable t) {
                throw Utils.wrap("DIGEST_create cleanup", t);
            }
        }
        return digestId;
    }

    static long DIGEST_copy(long digestId) throws OpenSSLException {
        if (digestId == 0) {
            throw new OpenSSLException("DIGEST_copy: The specified mdCtx is null");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);
        MemorySegment mdCtxCopy = NULL_PTR;
        long digestCopyId = 0;

        try {
            mdCtxCopy = (MemorySegment) MH_EVP_MD_CTX_new.invokeExact();
            if (mdCtxCopy.equals(NULL_PTR)) {
                throw new OpenSSLException("DIGEST_copy: EVP_MD_CTX_new failed");
            }

            int rc = (int) MH_EVP_MD_CTX_copy.invokeExact(mdCtxCopy, mdCtx);
            if (rc != 1) {
                throw new OpenSSLException("DIGEST_copy: EVP_MD_CTX_copy failed");
            }

            // Everything succeeded. Set digestCopyId to the copied EVP_MD_CTX.
            digestCopyId = mdCtxCopy.address();
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_copy", t);
        } finally {
            if (digestCopyId == 0 && !mdCtxCopy.equals(NULL_PTR)) {
                try {
                    MH_EVP_MD_CTX_free.invokeExact(mdCtxCopy);
                } catch (Throwable t) {
                    throw Utils.wrap("DIGEST_copy cleanup", t);
                }
            }
        }
        return digestCopyId;
    }

    private static int DIGEST_update_internal(MemorySegment mdCtx, MemorySegment dataNative,
            int dataLen) throws Throwable {
        if (mdCtx.address() == 0) {
            throw new OpenSSLException("DIGEST_update_internal: The specified mdCtx is null");
        }

        if (dataLen < 0) {
            throw new OpenSSLException(
                    "DIGEST_update_internal: The specified data length is negative");
        }

        int rc = (int) MH_EVP_DigestUpdate.invokeExact(mdCtx, dataNative, (long) dataLen);
        if (rc != 1) {
            throw new OpenSSLException("DIGEST_update_internal: EVP_DigestUpdate failed");
        }

        return rc;
    }

    static int DIGEST_update(long digestId, byte[] input, int offset, int length)
            throws OpenSSLException {
        if (input == null) {
            throw new OpenSSLException("DIGEST_update: The specified data array is null");
        }

        if (offset < 0) {
            throw new OpenSSLException("DIGEST_update: The specified offset is negative");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);

        try {
            MemorySegment dataNative = MemorySegment.ofArray(input).asSlice(offset, length);

            return DIGEST_update_internal(mdCtx, dataNative, length);
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_update", t);
        }
    }

    static void DIGEST_updateFastJNI(long digestId, long inputBuffer, int length)
            throws OpenSSLException {
        if (inputBuffer == 0) {
            throw new OpenSSLException(
                    "DIGEST_updateFastJNI: The pointer to the specified data buffer is null");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);

        try {
            MemorySegment dataNative = MemorySegment.ofAddress(inputBuffer).reinterpret(length);

            DIGEST_update_internal(mdCtx, dataNative, length);
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_updateFastJNI", t);
        }
    }

    static byte[] DIGEST_digest(long digestId) throws OpenSSLException {
        if (digestId == 0) {
            throw new OpenSSLException("DIGEST_digest: The specified mdCtx is null");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);

        try {
            int signedDigestLen = (int) MH_EVP_MD_CTX_get_size_ex.invokeExact(mdCtx);
            if (signedDigestLen <= 0) {
                throw new OpenSSLException("DIGEST_digest: EVP_MD_CTX_get_size_ex failed");
            }

            byte[] retDigestBytes = new byte[signedDigestLen];
            int rc = (int) MH_EVP_DigestFinal_ex.invokeExact(
                    mdCtx, MemorySegment.ofArray(retDigestBytes), NULL_PTR);
            if (rc != 1) {
                throw new OpenSSLException("DIGEST_digest: EVP_DigestFinal_ex failed");
            }

            return retDigestBytes;
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_digest", t);
        }
    }

    // The null check on the output buffer is done by the callers: a heap segment
    // backed by a Java array reports an address of 0, so it cannot be tested here.
    private static int digestAndResetInternal(long digestId, MemorySegment digestBytesNative)
            throws OpenSSLException {
        if (digestId == 0) {
            throw new OpenSSLException(
                    "DIGEST_digest_and_reset_internal: The specified mdCtx is null");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);

        try {
            int rc = (int) MH_EVP_DigestFinal_ex.invokeExact(
                    mdCtx, digestBytesNative, NULL_PTR);
            if (rc != 1) {
                throw new OpenSSLException(
                        "DIGEST_digest_and_reset_internal: EVP_DigestFinal_ex failed");
            }

            // Digest reset
            rc = (int) MH_EVP_DigestInit_ex2.invokeExact(mdCtx, NULL_PTR, NULL_PTR);
            if (rc != 1) {
                throw new OpenSSLException(
                        "DIGEST_digest_and_reset_internal: EVP_DigestInit_ex2 failed");
            }
            return rc;
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_digest_and_reset_internal", t);
        }
    }

    static void DIGEST_digest_and_reset(long digestId, long outputBuffer, int length)
            throws OpenSSLException {
        if (outputBuffer == 0) {
            throw new OpenSSLException(
                    "DIGEST_digest_and_reset_internal: The pointer to the specified data array is null");
        }

        try {
            digestAndResetInternal(digestId, MemorySegment.ofAddress(outputBuffer));
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_digest_and_reset", t);
        }
    }

    static int DIGEST_digest_and_reset(long digestId, byte[] output)
            throws OpenSSLException {
        if (output == null) {
            throw new OpenSSLException(
                    "DIGEST_digest_and_reset: The specified data array is null");
        }

        try {
            return digestAndResetInternal(digestId, MemorySegment.ofArray(output));
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_digest_and_reset", t);
        }
    }

    static int DIGEST_size(long digestId) throws OpenSSLException {
        if (digestId == 0) {
            throw new OpenSSLException("DIGEST_size: The specified mdCtx is null");
        }

        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);
        int digestLen = 0;

        try {
            digestLen = (int) MH_EVP_MD_CTX_get_size_ex.invokeExact(mdCtx);
            if (digestLen <= 0) {
                throw new OpenSSLException("DIGEST_size: EVP_MD_CTX_get_size failed");
            }
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_size", t);
        }
        return digestLen;
    }

    static void DIGEST_reset(long digestId) throws OpenSSLException {
        if (digestId == 0) {
            throw new OpenSSLException("DIGEST_reset: The specified mdCtx is null");
        }
        MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);

        try {
            int rc = (int) MH_EVP_DigestInit_ex2.invokeExact(mdCtx, NULL_PTR, NULL_PTR);
            if (rc != 1) {
                throw new OpenSSLException("DIGEST_reset: EVP_DigestInit_ex2 failed");
            }
        } catch (Throwable t) {
            throw Utils.wrap("DIGEST_reset", t);
        }
    }

    static void DIGEST_delete(long digestId) throws OpenSSLException {
        if (digestId != 0) {
            MemorySegment mdCtx = NativeOpenSSLFFMImplementation.toSegment(digestId);
            try {
                MH_EVP_MD_CTX_free.invokeExact(mdCtx);
            } catch (Throwable t) {
                throw Utils.wrap("DIGEST_delete", t);
            }
        }
    }

    private Digest() {}
}
