# Add your test source files here:
SOURCES = $(sort $(wildcard *.c))
CILS = $(sort $(wildcard *.cil))

###########################################################################

EXECUTABLE = libsemanage-tests
USER_JOIN_TEST = test-user-join-transaction
ERROR_TESTS = test-read-lock-error test-parse-read-error
CFLAGS += -g -O0 -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute
override CFLAGS += -I../src -I../include
override LDLIBS += -lcunit -lbz2 -laudit -lselinux -lsepol

OBJECTS = $(SOURCES:.c=.o)
POLICIES = $(CILS:.cil=.policy)

all: $(EXECUTABLE) $(POLICIES) $(USER_JOIN_TEST) $(ERROR_TESTS)

test-read-lock-error: regression/test_read_lock_error.c ../src/database.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

test-parse-read-error: regression/test_parse_read_error.c ../src/parse_utils.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

$(USER_JOIN_TEST): regression/test_user_join_transaction.c ../src/libsemanage.a
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(EXECUTABLE): $(OBJECTS) ../src/libsemanage.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.policy: %.cil
	../../secilc/secilc $*.cil -o $*.policy -f /dev/null

clean distclean:
	rm -rf $(OBJECTS) $(POLICIES) $(EXECUTABLE) $(USER_JOIN_TEST) $(ERROR_TESTS)

test: all
	./$(EXECUTABLE)
	./$(USER_JOIN_TEST)
	./test-parse-read-error
	./test-read-lock-error
