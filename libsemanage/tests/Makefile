# Add your test source files here:
SOURCES = $(sort $(wildcard *.c))
CILS = $(sort $(wildcard *.cil))

###########################################################################

EXECUTABLE = libsemanage-tests
ROLLBACK_TEST = test-final-rollback
RESTART_TEST = test-transaction-restart
USER_JOIN_TEST = test-user-join-transaction
LIFECYCLE_TEST = test-handle-lifecycle
ERROR_TESTS = test-read-lock-error test-user-delete-error test-parse-read-error
SERIAL_TESTS = test-cache-serial-file test-cache-serial-join test-cache-serial-active test-cache-serial-policydb
CFLAGS += -g -O0 -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I../src -I../include
override LDLIBS += -lcunit -lbz2 -laudit -lselinux -lsepol

OBJECTS = $(SOURCES:.c=.o)
POLICIES = $(CILS:.cil=.policy)

all: $(EXECUTABLE) $(POLICIES) $(USER_JOIN_TEST) $(LIFECYCLE_TEST) $(ERROR_TESTS) $(SERIAL_TESTS) $(ROLLBACK_TEST) $(RESTART_TEST)

$(RESTART_TEST): regression/test_transaction_restart.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--wrap=scandir -o $@ $^ $(LDLIBS)

$(ROLLBACK_TEST): regression/test_final_rollback.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -Wl,--wrap=fsync -Wl,--wrap=rename -Wl,--wrap=link -Wl,--wrap=unlinkat -Wl,--wrap=glob -o $@ $^ $(LDLIBS)

test-cache-serial-file: SERIAL_BACKEND = FILE
test-cache-serial-join: SERIAL_BACKEND = JOIN
test-cache-serial-active: SERIAL_BACKEND = ACTIVE
test-cache-serial-policydb: SERIAL_BACKEND = POLICYDB

$(SERIAL_TESTS): regression/test_cache_serial_error.c ../src/database_llist.c \
		../src/database_llist.h ../src/database_file.c \
		../src/database_join.c ../src/database_activedb.c \
		../src/database_policydb.c
	$(CC) $(CFLAGS) $(LDFLAGS) -DTEST_$(SERIAL_BACKEND) -o $@ $< ../src/database_llist.c -lsepol

$(LIFECYCLE_TEST): regression/test_handle_lifecycle.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

test-read-lock-error: regression/test_read_lock_error.c ../src/database.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test-parse-read-error: regression/test_parse_read_error.c ../src/parse_utils.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test-user-delete-error: regression/test_user_delete_error.c ../src/users_local.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(USER_JOIN_TEST): regression/test_user_join_transaction.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXECUTABLE): $(OBJECTS) ../src/libsemanage.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.policy: %.cil
	../../secilc/secilc $*.cil -o $*.policy -f /dev/null

clean distclean:
	rm -rf $(OBJECTS) $(POLICIES) $(EXECUTABLE) $(USER_JOIN_TEST) $(LIFECYCLE_TEST) $(ERROR_TESTS) $(SERIAL_TESTS) $(ROLLBACK_TEST) $(RESTART_TEST)

test: all test-ibpkey-validation
	./$(EXECUTABLE)
	./$(USER_JOIN_TEST)
	./$(LIFECYCLE_TEST)
	./test-parse-read-error
	./test-read-lock-error
	./test-user-delete-error
	@for test in $(SERIAL_TESTS); do ./$$test || exit 1; done
	./$(ROLLBACK_TEST)
	./$(RESTART_TEST)

test-ibpkey-validation:
	sh ibpkey-validation/run.sh

.PHONY: test-ibpkey-validation
