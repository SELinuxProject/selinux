# Build the checkpolicy fuzzer as a standalone debug binary.
# oss-fuzz.sh handles the sanitizer/libFuzzer build; this Makefile
# only produces a plain binary suitable for gdb/valgrind on a single
# reproducer input.

CHECKPOLICY := ..
LIBSEPOLA ?= ../../libsepol/src/libsepol.a
CFLAGS ?= -g -O0 -Wall
override CFLAGS += -I$(CHECKPOLICY) -I../../libsepol/include -D_GNU_SOURCE \
	-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -DDEFINEMAIN -DVERBOSE=1

# Parser objects - same set as $(CHECKOBJS) in ../Makefile, built
# locally with the fuzzing defines so module_compiler_reset() and the
# lexer's non-exit error paths are compiled in.
CHECKOBJS = y.tab.o lex.yy.o queue.o module_compiler.o parse_util.o \
	    policy_define.o

vpath %.c $(CHECKPOLICY)

all: checkpolicy-fuzzer

checkpolicy-fuzzer: checkpolicy-fuzzer.o $(CHECKOBJS) $(LIBSEPOLA)
	$(CC) $(LDFLAGS) -o $@ $^

# Ensure the generated parser/lexer sources exist in the parent dir.
$(CHECKPOLICY)/y.tab.c $(CHECKPOLICY)/y.tab.h $(CHECKPOLICY)/lex.yy.c:
	$(MAKE) -C $(CHECKPOLICY) $(@F)

y.tab.o: $(CHECKPOLICY)/y.tab.c $(CHECKPOLICY)/y.tab.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

lex.yy.o: $(CHECKPOLICY)/lex.yy.c $(CHECKPOLICY)/y.tab.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f checkpolicy-fuzzer *.o

.PHONY: all clean
