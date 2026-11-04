PCRE_LDLIBS ?= -lpcre2-8
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
override CFLAGS += -I../include -pthread
XDEV_WRAPS = getfilecon_raw lgetfilecon_raw openat openat64 fstat fstat64
EXCLUDE_WRAPS = getfilecon_raw lgetfilecon_raw openat openat64
WRAPS = getfilecon_raw setfilecon_raw getxattr fsetxattr pthread_cond_wait fstatfs fstatfs64
ERROR_WRAPS = getfilecon_raw setfilecon_raw lgetfilecon_raw lsetfilecon_raw
ERRNO_WRAPS = $(ERROR_WRAPS) close closedir fdopendir readdir readdir64 fstatfs fstatfs64 openat openat64 fstat fstat64 reallocarray

test-restorecon-digest: test_restorecon_digest.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(WRAPS)) $(PCRE_LDLIBS) -ldl -pthread

COMMA := ,

test-restorecon-errors: test_restorecon_errors.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(ERROR_WRAPS)) $(PCRE_LDLIBS) -ldl -pthread

test-restorecon-errno: test_restorecon_errno.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(ERRNO_WRAPS)) $(PCRE_LDLIBS) -ldl -pthread

.PHONY: test clean
test: test-restorecon-digest test-restorecon-errors test-restorecon-errno test-restorecon-exclude test-restorecon-xdev
	./test-restorecon-digest
	./test-restorecon-errors
	./test-restorecon-errno
	./test-restorecon-exclude
	./test-restorecon-xdev

clean:
	rm -f test-restorecon-digest test-restorecon-errors test-restorecon-errno test-restorecon-exclude test-restorecon-xdev

test-restorecon-exclude: test_restorecon_exclude.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(EXCLUDE_WRAPS)) $(PCRE_LDLIBS) -ldl -pthread
test-restorecon-xdev: test_restorecon_xdev.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(XDEV_WRAPS)) $(PCRE_LDLIBS) -ldl -pthread
