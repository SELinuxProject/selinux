#!/bin/bash

set -eux

export DESTDIR=$(pwd)/DESTDIR

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS=${CFLAGS:-$flags}

export CXX=${CXX:-clang++}
export CXXFLAGS=${CXXFLAGS:-$flags}

export LDFLAGS="${LDFLAGS:-} $CFLAGS"

export OUT=${OUT:-$(pwd)/out}
mkdir -p $OUT

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

find -name Makefile | xargs sed -i 's/,-z,defs//'
make V=1 -j$(nproc) install

$CC $CFLAGS -I$DESTDIR/usr/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -c -o secilc-fuzzer.o libsepol/fuzz/secilc-fuzzer.c
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE secilc-fuzzer.o $DESTDIR/usr/lib/libsepol.a -o $OUT/secilc-fuzzer
zip -r $OUT/secilc-fuzzer_seed_corpus.zip secilc/test
