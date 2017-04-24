PREFIX ?= $(DESTDIR)/usr
LIBDIR ?= $(PREFIX)/lib

# Add your test source files here:
SOURCES = $(wildcard *.c)

# Add the required external object files here:
LIBS = ../src/libsemanage.a -lselinux -lsepol

###########################################################################

EXECUTABLE = libsemanage-tests
CFLAGS += -g -O0 -Wall -W -Wundef -Wmissing-noreturn -Wmissing-format-attribute -Wno-unused-parameter
INCLUDE = -I../src -I../include
LDLIBS += -lcunit -lbz2 -laudit
OBJECTS = $(SOURCES:.c=.o) 

all: $(EXECUTABLE) 

$(EXECUTABLE): $(OBJECTS) ../src/libsemanage.a
	$(CC) $(OBJECTS) $(LIBS) $(LDFLAGS) -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $*.c -o $*.o

clean distclean: 
	rm -rf $(OBJECTS) $(EXECUTABLE)

test: all 
	./$(EXECUTABLE)

