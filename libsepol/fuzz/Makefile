# Build the libsepol fuzzers as standalone debug binaries.
# oss-fuzz.sh handles the sanitizer/libFuzzer build; this Makefile
# only produces plain binaries suitable for gdb/valgrind on a single
# reproducer input.
TARGETS := binpolicy-fuzzer secilc-fuzzer module-package-fuzzer

# Nothing in libsepol itself is conditional on
# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION so the normally-built
# ../src/libsepol.a can be used as-is.
LIBSEPOLA := ../src/libsepol.a

CFLAGS ?= -g -O0 -Wall
override CFLAGS += -I../include -I../cil/include -D_GNU_SOURCE \
	-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DDEFINEMAIN -DVERBOSE=1

all: $(TARGETS)

$(TARGETS): %: %.o $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
