#!/bin/bash

# The script is used to build the fuzz targets run on ClusterFuzz. It has to be
# compatible with the "build.sh" script described at
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh
# More precisely, it should use environment variables like OUT, LIB_FUZZING_ENGINE
# and so on (https://google.github.io/oss-fuzz/getting-started/new-project-guide/#buildsh-script-environment),
# and the fuzz targets have to be linked with $CXX even though the project is written
# in C: https://google.github.io/oss-fuzz/getting-started/new-project-guide/#Requirements

# To make it easier to build the fuzz targets locally, the script can also work in "local"
# mode. To run secilc-fuzzer against a test case (named, say, CRASH) triggering an issue
# the following commands should be run
#
# $ ./scripts/oss-fuzz.sh
# $ ./out/secilc-fuzzer CRASH

# To run the fuzzer against the corpus OSS-Fuzz has accumulated so far it should be
# downloaded, unpacked and passed to the fuzzer:
#
# $ wget https://storage.googleapis.com/selinux-backup.clusterfuzz-external.appspot.com/corpus/libFuzzer/selinux_secilc-fuzzer/public.zip
# $ unzip -d CORPUS public.zip
# $ ./out/secilc-fuzzer CORPUS/

set -eux

cd "$(dirname -- "$0")/.."

export DESTDIR=${DESTDIR:-$(pwd)/DESTDIR}

SANITIZER=${SANITIZER:-address}
flags="-O1 -fno-omit-frame-pointer -gline-tables-only -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=$SANITIZER -fsanitize=fuzzer-no-link"

export CC=${CC:-clang}
export CFLAGS="${CFLAGS:-$flags} -I$DESTDIR/usr/include -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64"

export CXX=${CXX:-clang++}
export CXXFLAGS="${CXXFLAGS:-$flags}"

export OUT=${OUT:-$(pwd)/out}
mkdir -p "$OUT"

export LIB_FUZZING_ENGINE=${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}

rm -rf "$DESTDIR"
make -C libsepol clean
# LIBSO and LIBMAP shouldn't be expanded here because their values are unknown until Makefile
# has been read by make
# shellcheck disable=SC2016
make -C libsepol V=1 LD_SONAME_FLAGS='-soname,$(LIBSO),--version-script=$(LIBMAP)' -j"$(nproc)" install

## secilc fuzzer ##

# CFLAGS, CXXFLAGS and LIB_FUZZING_ENGINE have to be split to be accepted by
# the compiler/linker so they shouldn't be quoted
# shellcheck disable=SC2086
$CC $CFLAGS -c -o secilc-fuzzer.o libsepol/fuzz/secilc-fuzzer.c
# shellcheck disable=SC2086
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE secilc-fuzzer.o "$DESTDIR/usr/lib/libsepol.a" -o "$OUT/secilc-fuzzer"

zip -r "$OUT/secilc-fuzzer_seed_corpus.zip" secilc/test

## binary policy fuzzer ##

# CFLAGS, CXXFLAGS and LIB_FUZZING_ENGINE have to be split to be accepted by
# the compiler/linker so they shouldn't be quoted
# shellcheck disable=SC2086
$CC $CFLAGS -c -o binpolicy-fuzzer.o libsepol/fuzz/binpolicy-fuzzer.c
# shellcheck disable=SC2086
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE binpolicy-fuzzer.o "$DESTDIR/usr/lib/libsepol.a" -o "$OUT/binpolicy-fuzzer"

zip -j "$OUT/secilc-fuzzer_seed_corpus.zip" libsepol/fuzz/policy.bin
