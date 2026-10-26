###############################################################################
#
# Copyright IBM Corp. 2026
#
# This code is free software; you can redistribute it and/or modify it
# under the terms provided by IBM in the LICENSE file that accompanied
# this code, including the "Classpath" Exception described therein.
###############################################################################
#
# z/OS-specific makefile for the OpenSSL JNI bridge.
#
# The zopen distribution ships OpenSSL exclusively as a static archive
# (libcrypto.a).  This makefile statically absorbs libcrypto.a into the
# resulting libopenjceplus.so at link time so that Java can load a single
# self-contained shared object with no runtime dependency on libcrypto.
#
# Usage:
#   export OPENSSL_HOME=...
#   make -f openjceplus.zos.mak clean
#   make -f openjceplus.zos.mak
###############################################################################

PLATFORM     = s390-zos64

# Inherit all targets, object lists, compiler flags, and include paths from
# the platform-agnostic makefile.  We override only the linker inputs below.
include openjceplus.mak

# Override TARGET_LIBS: list libcrypto.a directly so the z/OS binder absorbs
# it as a static contribution.  On z/OS pthread is part of the system libc
# (Language Environment) and does not need to be linked separately.
TARGET_LIBS := $(OPENSSL_HOME)/lib/libcrypto.a
