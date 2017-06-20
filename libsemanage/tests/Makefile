PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib

# Add your test source files here:
SOURCES = $(sort $(wildcard *.c))

###########################################################################

EXECUTABLE = libsemanage-tests
CFLAGS += -g -O0 -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wno-unused-parameter
override CFLAGS += -I../src -I../include
override LDLIBS += -lcunit -lbz2 -laudit -lselinux -lsepol

OBJECTS = $(SOURCES:.c=.o) 

all: $(EXECUTABLE) 

$(EXECUTABLE): $(OBJECTS) ../src/libsemanage.a
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean distclean: 
	rm -rf $(OBJECTS) $(EXECUTABLE)

test: all 
	./$(EXECUTABLE)

