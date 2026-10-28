PCRE_LDLIBS ?= -lpcre2-8
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
override CFLAGS += -I../include -pthread
WRAPS = getfilecon_raw setfilecon_raw getxattr fsetxattr pthread_cond_wait fstatfs fstatfs64

test-restorecon-digest: test_restorecon_digest.c ../src/libselinux.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(addprefix -Wl$(COMMA)--wrap=,$(WRAPS)) $(PCRE_LDLIBS) -ldl -pthread

COMMA := ,

.PHONY: test clean
test: test-restorecon-digest
	./test-restorecon-digest

clean:
	rm -f test-restorecon-digest
