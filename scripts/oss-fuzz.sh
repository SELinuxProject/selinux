#!/bin/bash

set -eux

export DESTDIR=${DESTDIR:-$(pwd)/DESTDIR}

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags}

export OUT=${OUT:-$(pwd)/out}
mkdir -p "$OUT"

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

find . -name Makefile -print0 | xargs -0 sed -i 's/,-z,defs//'
rm -rf "$DESTDIR"
make -C libsepol clean
make -C libsepol V=1 -j"$(nproc)" install

# CFLAGS, CXXFLAGS and LIB_FUZZING_ENGINE have to be split to be accepted by
# the compiler/linker so they shouldn't be quoted
# shellcheck disable=SC2086
$CC $CFLAGS -I"$DESTDIR/usr/include" -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -c -o secilc-fuzzer.o libsepol/fuzz/secilc-fuzzer.c
# shellcheck disable=SC2086
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE secilc-fuzzer.o "$DESTDIR/usr/lib/libsepol.a" -o "$OUT/secilc-fuzzer"

zip -r "$OUT/secilc-fuzzer_seed_corpus.zip" secilc/test
