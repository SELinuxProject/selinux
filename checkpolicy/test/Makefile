#
# Makefile for building the dispol program
#
PREFIX ?= $(DESTDIR)/usr
BINDIR ?= $(PREFIX)/bin
LIBDIR ?= $(PREFIX)/lib
INCLUDEDIR ?= $(PREFIX)/include
LIBSEPOLA ?= $(LIBDIR)/libsepol.a

CFLAGS ?= -g -Wall -W -Werror -O2 -pipe

all: dispol dismod

dispol: dispol.o $(LIBSEPOLA)

dismod: dismod.o $(LIBSEPOLA)

clean:
	-rm -f dispol dismod *.o 
