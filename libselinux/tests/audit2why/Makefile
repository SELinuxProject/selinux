PYTHON ?= python3
PYTHON_CONFIG ?= $(PYTHON)-config
LIBSEPOL ?= ../../../libsepol/src/libsepol.a
LIBSELINUX ?= ../../src/libselinux.so.1
BUILD = build
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
override CPPFLAGS += -I../../../libsepol/include -I../../include
PY_CFLAGS := $(shell $(PYTHON_CONFIG) --includes)
WRAPS = sepol_sidtab_init sepol_handle_create sepol_bool_iterate strdup sepol_policy_file_create sepol_policy_file_free

$(BUILD):
	mkdir -p $@

$(BUILD)/audit2why.o: ../../src/audit2why.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PY_CFLAGS) -fPIC -Dmalloc=audit_malloc -Dcalloc=audit_calloc -Dstrdup=audit_strdup -Dfree=audit_free -c $< -o $@

$(BUILD)/fault.o: fault.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -D_GNU_SOURCE -fPIC -c $< -o $@

$(BUILD)/audit2why.so: $(BUILD)/audit2why.o $(BUILD)/fault.o $(LIBSEPOL) $(LIBSELINUX)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(foreach sym,$(WRAPS),-Wl,--wrap=$(sym)) -Wl,-rpath,$(abspath $(dir $(LIBSELINUX)))

$(BUILD)/policy: policy.c $(LIBSEPOL) | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBSEPOL)

$(BUILD)/policy.bin: policy.cil $(BUILD)/policy
	./$(BUILD)/policy $< $@

test: $(BUILD)/audit2why.so $(BUILD)/policy.bin
	PYTHONPATH=$(abspath $(BUILD)) $(PYTHON) test.py $(abspath $(BUILD)/policy.bin)

clean:
	rm -rf $(BUILD)

.PHONY: test clean
