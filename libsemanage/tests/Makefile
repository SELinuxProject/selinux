# Add your test source files here:
SOURCES = $(sort $(wildcard *.c))
CILS = $(sort $(wildcard *.cil))

###########################################################################

EXECUTABLE = libsemanage-tests
CFLAGS += -g -O0 -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I../src -I../include
override LDLIBS += -lcunit -lbz2 -laudit -lselinux -lsepol

OBJECTS = $(SOURCES:.c=.o)
POLICIES = $(CILS:.cil=.policy)

all: $(EXECUTABLE) $(POLICIES) test-config-empty

$(EXECUTABLE): $(OBJECTS) ../src/libsemanage.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.policy: %.cil
	../../secilc/secilc $*.cil -o $*.policy -f /dev/null

clean distclean:
	rm -rf $(OBJECTS) $(POLICIES) $(EXECUTABLE) test-config-empty
	rm -f test-genhomedircon-parent

test: all test-genhomedircon-parent
	./$(EXECUTABLE)
	./test-config-empty
	./test-genhomedircon-parent

test-config-empty: regression/test_config_empty.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -Wl,--wrap=strdup $(LDLIBS)

PARENT_WRAPS = semanage_findval sepol_context_check getpwent setpwent endpwent fopen stat semanage_fcontext_iterate asprintf
COMMA := ,
test-genhomedircon-parent: regression/test_genhomedircon_parent.c ../src/genhomedircon.c ../src/path_subs.c ../src/libsemanage.a
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_GNU_SOURCE -ffunction-sections -fdata-sections $(LDFLAGS) -Wl,--gc-sections -o $@ $< ../src/path_subs.c ../src/libsemanage.a $(addprefix -Wl$(COMMA)--wrap=,$(PARENT_WRAPS)) $(LDLIBS)

# Requires SWIG, Python development headers and the built shared library.
PYTHON ?= python3
.PHONY: test-python-module-buffer
test-python-module-buffer:
	$(PYTHON) regression/test_module_buffer.py
