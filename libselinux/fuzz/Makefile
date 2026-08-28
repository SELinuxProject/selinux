# Build the libselinux fuzzers as standalone debug binaries.
# oss-fuzz.sh handles the sanitizer/libFuzzer build; this Makefile
# only produces plain binaries suitable for gdb/valgrind on a single
# reproducer input.
TARGETS := selabel_file_text-fuzzer selabel_file_compiled-fuzzer

LIBSELINUXA := ../src/libselinux.a

PCRE_CFLAGS ?= -DUSE_PCRE2 -DPCRE2_CODE_UNIT_WIDTH=8
PCRE_LDLIBS ?= -lpcre2-8

CFLAGS ?= -g -O0 -Wall
override CFLAGS += -I../include -I../src -D_GNU_SOURCE -DNO_ANDROID_BACKEND \
	$(PCRE_CFLAGS) -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION \
	-DDEFINEMAIN -DVERBOSE=1

all: $(TARGETS)

# Only label_file.o changes behavior under
# FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION. Compile a private copy
# of it here and link the rest from the normally-built ../src/libselinux.a.
label_file.o: ../src/label_file.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(TARGETS): %: %.o label_file.o $(LIBSELINUXA)
	$(CC) $(LDFLAGS) -o $@ $^ $(PCRE_LDLIBS)

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean
